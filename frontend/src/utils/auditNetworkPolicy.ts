// AuditNetworkPolicy is byte-identical to NetworkPolicy apart from its
// apiVersion/kind (docs/concepts/audit-network-policy.mdx): the evaluator
// reports what the policy WOULD deny instead of dropping anything, and
// promotion (kubectl kguardian audit promote) is the reverse rename. Keeping
// the same name and spec is what makes that round trip lossless.

import type { NetworkPolicy } from '../types/networkPolicy';

export const AUDIT_POLICY_API_VERSION = 'kguardian.dev/v1alpha1';
export const AUDIT_POLICY_KIND = 'AuditNetworkPolicy';

export function toAuditNetworkPolicy(policy: NetworkPolicy): NetworkPolicy {
  return { ...policy, apiVersion: AUDIT_POLICY_API_VERSION, kind: AUDIT_POLICY_KIND };
}
