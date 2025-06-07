package network

import (
	"fmt"

	log "github.com/rs/zerolog/log"
	"github.com/xentra-ai/advisor/pkg/api"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StandardPolicyGenerator generates standard Kubernetes NetworkPolicy resources
type StandardPolicyGenerator struct {
	trafficProcessor *TrafficProcessor
	ruleGrouper      *RuleGrouper
	peerResolver     *PeerResolver
}

// NewStandardPolicyGenerator creates a new generator for standard NetworkPolicy resources
func NewStandardPolicyGenerator() *StandardPolicyGenerator {
	return &StandardPolicyGenerator{
		trafficProcessor: &TrafficProcessor{},
		ruleGrouper:      &RuleGrouper{},
		peerResolver:     &PeerResolver{},
	}
}

// GetType returns the policy type
func (g *StandardPolicyGenerator) GetType() PolicyType {
	return StandardPolicy
}

// Generate creates a NetworkPolicy for the specified pod
func (g *StandardPolicyGenerator) Generate(podName string, podTraffic []api.PodTraffic, podDetail *api.PodDetail) (interface{}, error) {
	log.Info().Msgf("Generating standard network policy for pod %s", podName)

	if podDetail == nil {
		return nil, fmt.Errorf("pod detail is nil for pod %s", podName)
	}

	if len(podTraffic) == 0 {
		log.Warn().Msgf("No traffic data available for pod %s. Generating a default-deny policy.", podName)
		return g.generateDefaultDenyPolicy(podDetail), nil
	}

	// Process traffic using shared logic
	ingressRules, egressRules := g.trafficProcessor.ProcessTrafficRules(podTraffic, podDetail)

	// Create the NetworkPolicy object
	policy := &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy"),
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels,
			},
			PolicyTypes: g.buildPolicyTypes(ingressRules, egressRules),
		},
	}

	// Add rules if any exist
	if len(ingressRules) > 0 {
		policy.Spec.Ingress = g.buildIngressRules(ingressRules)
	}
	if len(egressRules) > 0 {
		policy.Spec.Egress = g.buildEgressRules(egressRules)
	}

	// Generate default-deny if no valid rules
	if len(policy.Spec.PolicyTypes) == 0 {
		log.Warn().Msgf("No valid ingress or egress rules generated for pod %s. Applying default-deny.", podName)
		return g.generateDefaultDenyPolicy(podDetail), nil
	}

	return policy, nil
}

// generateDefaultDenyPolicy creates a policy that denies all ingress and egress traffic
func (g *StandardPolicyGenerator) generateDefaultDenyPolicy(podDetail *api.PodDetail) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		TypeMeta: CreateTypeMeta("NetworkPolicy", "networking.k8s.io/v1"),
		ObjectMeta: CreateObjectMeta(
			GetPolicyName(podDetail.Name, "standard-policy-deny-all"),
			podDetail.Namespace,
			CreateStandardLabels(podDetail.Name, "standard-policy-deny-all"),
		),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podDetail.Pod.Labels,
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	}
}

// buildPolicyTypes determines which policy types are needed based on available rules
func (g *StandardPolicyGenerator) buildPolicyTypes(ingressRules, egressRules []NetworkPolicyRule) []networkingv1.PolicyType {
	var policyTypes []networkingv1.PolicyType

	if len(ingressRules) > 0 {
		policyTypes = append(policyTypes, networkingv1.PolicyTypeIngress)
	}
	if len(egressRules) > 0 {
		policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress)
	}

	return policyTypes
}

// buildIngressRules converts internal rules to Kubernetes NetworkPolicyIngressRule
func (g *StandardPolicyGenerator) buildIngressRules(rules []NetworkPolicyRule) []networkingv1.NetworkPolicyIngressRule {
	peerRules := g.ruleGrouper.GroupRulesByPeer(rules)
	var ingressRules []networkingv1.NetworkPolicyIngressRule

	for peerIP, ports := range peerRules {
		peer := g.peerResolver.ResolveStandardPeer(peerIP)
		if peer == nil {
			log.Warn().Msgf("Failed to resolve peer %s, skipping ingress rule", peerIP)
			continue
		}

		ingressRules = append(ingressRules, networkingv1.NetworkPolicyIngressRule{
			From:  []networkingv1.NetworkPolicyPeer{*peer},
			Ports: deduplicatePorts(ports),
		})
	}

	return ingressRules
}

// buildEgressRules converts internal rules to Kubernetes NetworkPolicyEgressRule
func (g *StandardPolicyGenerator) buildEgressRules(rules []NetworkPolicyRule) []networkingv1.NetworkPolicyEgressRule {
	peerRules := g.ruleGrouper.GroupRulesByPeer(rules)
	var egressRules []networkingv1.NetworkPolicyEgressRule

	for peerIP, ports := range peerRules {
		peer := g.peerResolver.ResolveStandardPeer(peerIP)
		if peer == nil {
			log.Warn().Msgf("Failed to resolve peer %s, skipping egress rule", peerIP)
			continue
		}

		egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{*peer},
			Ports: deduplicatePorts(ports),
		})
	}

	return egressRules
}
