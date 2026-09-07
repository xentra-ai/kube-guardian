import type { PolicyType } from '../hooks/policyEditor/usePolicyExport';
import { recommendedPolicyType } from './cniPolicySupport';

/** The kinds of finding the Findings view surfaces per workload. */
export type FindingKind = 'denied-traffic' | 'sensitive-syscalls' | 'egress-fanout' | 'would-deny';

/**
 * Which Policy Builder tab a finding's "Policy" action should open. A
 * sensitive-syscalls finding is a seccomp concern; every network finding
 * opens the network policy — CiliumNetworkPolicy when the cluster CNI is
 * Cilium (the #1421 preference), plain NetworkPolicy otherwise (including
 * 'unknown', which must behave exactly as before detection).
 */
export function policyTypeForFinding(kind: FindingKind, cni: string = 'unknown'): PolicyType {
  if (kind === 'sensitive-syscalls') return 'seccomp';
  // Delegated, not restated. This rule also decides the Policy Builder's
  // default tab, and two copies of "which kind can this cluster enforce"
  // drift the moment a CNI is added to one and not the other.
  return recommendedPolicyType(cni);
}
