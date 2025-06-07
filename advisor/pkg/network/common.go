package network

import (
	"fmt"

	log "github.com/rs/zerolog/log"
	"github.com/xentra-ai/advisor/pkg/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TrafficProcessor handles common traffic processing logic for both standard and Cilium generators
type TrafficProcessor struct{}

// ProcessedTraffic represents a validated and processed traffic record
type ProcessedTraffic struct {
	PeerIP   string
	Port     intstr.IntOrString
	Protocol corev1.Protocol
	IsValid  bool
	Error    error
}

// ProcessTrafficRules processes traffic data and returns ingress/egress rules using shared logic
func (tp *TrafficProcessor) ProcessTrafficRules(podTraffic []api.PodTraffic, podDetail *api.PodDetail) ([]NetworkPolicyRule, []NetworkPolicyRule) {
	var ingressRules, egressRules []NetworkPolicyRule

	for _, traffic := range podTraffic {
		processed := tp.processTrafficRecord(traffic, podDetail)
		if !processed.IsValid {
			if processed.Error != nil {
				log.Warn().Err(processed.Error).Msg("Skipping invalid traffic record")
			}
			continue
		}

		// Add to appropriate rules list
		if IsIngressTraffic(traffic, podDetail) {
			log.Debug().Msgf("Processing INGRESS: allowing peer %s to reach our pod port %s (%s)",
				processed.PeerIP, processed.Port.String(), processed.Protocol)
			ingressRules = tp.addOrUpdateRule(ingressRules, processed.PeerIP, processed.Port, processed.Protocol)
		} else if IsEgressTraffic(traffic, podDetail) {
			log.Debug().Msgf("Processing EGRESS: allowing our pod to reach peer %s on port %s (%s)",
				processed.PeerIP, processed.Port.String(), processed.Protocol)
			egressRules = tp.addOrUpdateRule(egressRules, processed.PeerIP, processed.Port, processed.Protocol)
		}
	}

	log.Info().Msgf("Generated %d ingress rules and %d egress rules for pod %s",
		len(ingressRules), len(egressRules), podDetail.Name)

	return ingressRules, egressRules
}

// processTrafficRecord validates and extracts data from a single traffic record
func (tp *TrafficProcessor) processTrafficRecord(traffic api.PodTraffic, podDetail *api.PodDetail) ProcessedTraffic {
	var peer string
	var portStr string

	// Determine peer and port based on traffic direction
	if IsIngressTraffic(traffic, podDetail) {
		peer = traffic.DstIP         // External source
		portStr = traffic.SrcPodPort // Port on our pod
	} else if IsEgressTraffic(traffic, podDetail) {
		peer = traffic.DstIP      // External destination
		portStr = traffic.DstPort // Port on destination
	} else {
		return ProcessedTraffic{
			IsValid: false,
			Error:   fmt.Errorf("unknown traffic type: %s", traffic.TrafficType),
		}
	}

	// Validate peer IP
	if peer == "" {
		return ProcessedTraffic{IsValid: false} // Skip silently for empty IPs
	}
	if peer == podDetail.PodIP {
		log.Debug().Msgf("Skipping self-traffic (peer %s == pod IP %s)", peer, podDetail.PodIP)
		return ProcessedTraffic{IsValid: false}
	}

	// Parse and validate port
	portInt, err := parsePort(portStr)
	if err != nil {
		return ProcessedTraffic{
			IsValid: false,
			Error:   fmt.Errorf("invalid port %s: %w", portStr, err),
		}
	}

	// Validate protocol
	protocol := protocolPtr(string(traffic.Protocol))
	if protocol == nil {
		return ProcessedTraffic{
			IsValid: false,
			Error:   fmt.Errorf("invalid protocol: %s", traffic.Protocol),
		}
	}

	return ProcessedTraffic{
		PeerIP:   peer,
		Port:     intstr.FromInt(portInt),
		Protocol: *protocol,
		IsValid:  true,
	}
}

// addOrUpdateRule adds a port to an existing rule for a peer or creates a new rule
func (tp *TrafficProcessor) addOrUpdateRule(rules []NetworkPolicyRule, peer string, port intstr.IntOrString, protocol corev1.Protocol) []NetworkPolicyRule {
	// Look for existing rule for this peer
	for i := range rules {
		if rules[i].PeerIP == peer {
			// Check if this port/protocol combo already exists
			if !tp.portExists(rules[i].Ports, port, protocol) {
				rules[i].Ports = append(rules[i].Ports, networkingv1.NetworkPolicyPort{
					Port:     &port,
					Protocol: &protocol,
				})
			}
			return rules
		}
	}

	// Create new rule for this peer
	newRule := NetworkPolicyRule{
		PeerIP: peer,
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Port:     &port,
				Protocol: &protocol,
			},
		},
	}
	return append(rules, newRule)
}

// portExists checks if a port/protocol combination already exists in the ports slice
func (tp *TrafficProcessor) portExists(ports []networkingv1.NetworkPolicyPort, port intstr.IntOrString, protocol corev1.Protocol) bool {
	for _, existingPort := range ports {
		if existingPort.Port != nil && existingPort.Port.String() == port.String() &&
			existingPort.Protocol != nil && *existingPort.Protocol == protocol {
			return true
		}
	}
	return false
}

// RuleGrouper handles grouping of rules by peer IP for rule transformation
type RuleGrouper struct{}

// GroupRulesByPeer groups NetworkPolicyRules by peer IP and combines their ports
func (rg *RuleGrouper) GroupRulesByPeer(rules []NetworkPolicyRule) map[string][]networkingv1.NetworkPolicyPort {
	peerRules := make(map[string][]networkingv1.NetworkPolicyPort)
	for _, rule := range rules {
		peerRules[rule.PeerIP] = append(peerRules[rule.PeerIP], rule.Ports...)
	}
	return peerRules
}

// PeerResolver handles resolution of IP addresses to appropriate peer selectors
type PeerResolver struct{}

// ResolveStandardPeer resolves an IP to a standard Kubernetes NetworkPolicyPeer
func (pr *PeerResolver) ResolveStandardPeer(peerIP string) *networkingv1.NetworkPolicyPeer {
	log.Debug().Msgf("Resolving standard peer for IP: %s", peerIP)

	// Try service first (prioritized for better performance)
	if peer := pr.tryServiceResolution(peerIP); peer != nil {
		return peer
	}

	// Try pod resolution
	if peer := pr.tryPodResolution(peerIP); peer != nil {
		return peer
	}

	// Fall back to IPBlock
	log.Debug().Msgf("Using IPBlock for peer %s", peerIP)
	return &networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{
			CIDR: fmt.Sprintf("%s/32", peerIP),
		},
	}
}

// tryServiceResolution attempts to resolve IP to a service-based peer
func (pr *PeerResolver) tryServiceResolution(peerIP string) *networkingv1.NetworkPolicyPeer {
	svcSpec, err := api.GetSvcSpec(peerIP)
	if err != nil || svcSpec == nil || len(svcSpec.Service.Spec.Selector) == 0 {
		return nil
	}

	log.Debug().Msgf("Resolved IP %s to service %s/%s",
		peerIP, svcSpec.SvcNamespace, svcSpec.SvcName)

	return &networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: svcSpec.Service.Spec.Selector,
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": svcSpec.SvcNamespace,
			},
		},
	}
}

// tryPodResolution attempts to resolve IP to a pod-based peer
func (pr *PeerResolver) tryPodResolution(peerIP string) *networkingv1.NetworkPolicyPeer {
	podSpec, err := api.GetPodSpec(peerIP)
	if err != nil || podSpec == nil || len(podSpec.Pod.Labels) == 0 {
		return nil
	}

	log.Debug().Msgf("Resolved IP %s to pod %s/%s",
		peerIP, podSpec.Namespace, podSpec.Name)

	return &networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: podSpec.Pod.Labels,
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"kubernetes.io/metadata.name": podSpec.Namespace,
			},
		},
	}
}

// Utility functions

// protocolPtr safely converts a protocol string to a pointer, with validation
func protocolPtr(protocol string) *corev1.Protocol {
	var p corev1.Protocol
	switch protocol {
	case "TCP":
		p = corev1.ProtocolTCP
	case "UDP":
		p = corev1.ProtocolUDP
	case "SCTP":
		p = corev1.ProtocolSCTP
	default:
		log.Warn().Msgf("Unknown protocol '%s', defaulting to TCP", protocol)
		p = corev1.ProtocolTCP
	}
	return &p
}

// parsePort converts a string port to an integer with validation
func parsePort(portStr string) (int, error) {
	var portInt int
	_, err := fmt.Sscanf(portStr, "%d", &portInt)
	if err != nil {
		return 0, fmt.Errorf("invalid port format '%s': %w", portStr, err)
	}
	if portInt <= 0 || portInt > 65535 {
		return 0, fmt.Errorf("port number '%d' out of valid range (1-65535)", portInt)
	}
	return portInt, nil
}

// deduplicatePorts removes duplicate ports from a slice with improved efficiency
func deduplicatePorts(ports []networkingv1.NetworkPolicyPort) []networkingv1.NetworkPolicyPort {
	if len(ports) <= 1 {
		return ports
	}

	seen := make(map[string]struct{}, len(ports))
	result := make([]networkingv1.NetworkPolicyPort, 0, len(ports))

	for _, port := range ports {
		if port.Port == nil || port.Protocol == nil {
			log.Warn().Msg("Skipping port with nil port or protocol during deduplication")
			continue
		}

		key := fmt.Sprintf("%s-%s", port.Port.String(), string(*port.Protocol))
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, port)
		}
	}

	return result
}
