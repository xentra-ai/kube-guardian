// Package policycoverage answers one question about a real
// networking.k8s.io NetworkPolicy set: could a policy have caused this?
//
// It exists because kguardian's drop signal asserted a cause it never
// established. `netpolicy_drop.bpf.c` reports a flow when a TCP
// handshake retransmits its SYN four times without reaching ESTABLISHED.
// That is an honest observation of silence, but nothing downstream knew
// WHY the handshake failed, and every layer — the file name, the
// `decision: DROP` column, the "Network Policy Drop" log line, the
// `denied-traffic` finding — presented it as a policy denial.
//
// The gap was that kguardian read no NetworkPolicy objects at all. It
// could not have known: with zero policies in a cluster, every reported
// "policy drop" is definitionally something else (a port nothing
// listens on and blackholes, a security group, a route, an overloaded
// peer), and an operator chasing a policy misconfiguration is chasing
// nothing.
//
// This package does not try to decide whether a policy denied a
// specific flow — the matcher already does per-flow evaluation for
// AuditNetworkPolicy, and duplicating it here would drift. It answers
// the cheaper, decisive question: does ANY policy govern this pod in
// this direction? A "no" is conclusive and reclassifies the drop. A
// "yes" is a genuine lead rather than a guess.
package policycoverage

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Direction is the side of the flow being asked about.
type Direction string

const (
	// Egress: the pod originated the connection. This is the direction
	// the drop probe observes, since it hooks outbound connect and
	// retransmit.
	Egress Direction = "Egress"
	// Ingress: the pod was the destination.
	Ingress Direction = "Ingress"
)

// Cause classifies a reported drop by what the policy set makes
// possible. Deliberately about possibility rather than certainty: the
// probe cannot see a denial, so neither can this.
type Cause string

const (
	// CauseNoPolicy: no NetworkPolicy governs this pod in this
	// direction, so a policy cannot have caused the failure. The
	// strongest and most useful answer, because it is conclusive and
	// redirects the operator away from their policies entirely.
	CauseNoPolicy Cause = "no-policy"
	// CausePolicyGoverns: at least one policy selects this pod for this
	// direction, so a denial is plausible. Not a confirmation — the
	// policy may well permit this flow and the failure lie elsewhere.
	CausePolicyGoverns Cause = "policy-governs"
	// CauseUnknown: coverage could not be established — no RBAC for
	// networkpolicies, the informer has not synced, or the evaluator is
	// not deployed. Honest ignorance, and it must never be presented as
	// either of the above.
	CauseUnknown Cause = "unknown"
)

// Governs reports whether any policy in `policies` selects `pod` for
// `dir`.
//
// `policies` must already be scoped to the pod's namespace: a
// NetworkPolicy only ever selects pods in its own namespace, however
// broad its peer rules are. Callers that pass a cluster-wide list will
// get wrong answers, which is why the store's accessor is
// namespace-keyed.
func Governs(policies []*networkingv1.NetworkPolicy, pod *corev1.Pod, dir Direction) bool {
	if pod == nil {
		return false
	}
	podLabels := labels.Set(pod.Labels)
	for _, p := range policies {
		if p == nil || p.Namespace != pod.Namespace {
			continue
		}
		if !governsDirection(p, dir) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			// A selector the API server accepted but we cannot parse.
			// Counting it as governing is the safe direction: it keeps a
			// possible cause visible instead of telling the operator
			// their policies are definitively not involved.
			return true
		}
		if sel.Matches(podLabels) {
			return true
		}
	}
	return false
}

// governsDirection applies the upstream policyTypes defaulting rule,
// which is easy to get wrong and changes the answer.
//
// From the NetworkPolicy spec: when policyTypes is not set, Ingress is
// always implied, and Egress is implied only if the policy has egress
// rules. So an ingress-only policy with no policyTypes does NOT govern
// egress, and treating an empty list as "governs everything" would make
// every namespace with any policy look like it governed egress.
func governsDirection(p *networkingv1.NetworkPolicy, dir Direction) bool {
	if len(p.Spec.PolicyTypes) > 0 {
		for _, t := range p.Spec.PolicyTypes {
			if string(t) == string(dir) {
				return true
			}
		}
		return false
	}
	switch dir {
	case Ingress:
		return true
	case Egress:
		return len(p.Spec.Egress) > 0
	default:
		return false
	}
}

// Classify turns a coverage answer into a Cause.
//
// `known` is false when the policy set could not be read at all, which
// is a different answer from "read it and found nothing" and must not
// collapse into CauseNoPolicy — that would tell an operator their
// policies are definitively uninvolved on the strength of a failed API
// call.
func Classify(known bool, governs bool) Cause {
	if !known {
		return CauseUnknown
	}
	if governs {
		return CausePolicyGoverns
	}
	return CauseNoPolicy
}
