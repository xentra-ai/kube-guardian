import { describe, it, expect } from 'vitest';
import {
  recommendedPolicyType,
  enforcementAdvisory,
  isDismissible,
  type PolicyType,
} from './cniPolicySupport';

const env = (cni: string, policy_enforcement: string) => ({ cni, policy_enforcement });

describe('recommendedPolicyType', () => {
  it('picks CiliumNetworkPolicy only where Cilium is the CNI', () => {
    expect(recommendedPolicyType('cilium')).toBe('cilium');
  });

  it('picks standard NetworkPolicy for AWS VPC CNI', () => {
    // The case this work exists for: VPC CNI enforces standard
    // NetworkPolicy and has no idea what a CiliumNetworkPolicy is.
    expect(recommendedPolicyType('aws-vpc-cni')).toBe('network');
  });

  it('picks standard NetworkPolicy for other CNIs and when unknown', () => {
    for (const cni of ['calico', 'antrea', 'flannel', 'weave', 'unknown']) {
      expect(recommendedPolicyType(cni)).toBe('network');
    }
  });
});

describe('enforcementAdvisory', () => {
  it('says nothing when the CNI enforces the selected kind', () => {
    expect(enforcementAdvisory('network', env('aws-vpc-cni', 'enforced'))).toBeNull();
    expect(enforcementAdvisory('cilium', env('cilium', 'enforced'))).toBeNull();
  });

  it('never comments on seccomp, which the CNI has no bearing on', () => {
    expect(enforcementAdvisory('seccomp', env('flannel', 'unenforced'))).toBeNull();
  });

  it('escalates to error when the policy would be silently inert', () => {
    // The core bug. Applying succeeds, kubectl shows the object, and
    // nothing is restricted — so this must not read like a style note.
    const a = enforcementAdvisory('network', env('aws-vpc-cni', 'unenforced'));
    expect(a?.severity).toBe('error');
    expect(a?.detail).toMatch(/no traffic will be restricted/i);
    expect(isDismissible(a!)).toBe(false);
  });

  it('escalates to error on a split fleet, where placement decides', () => {
    const a = enforcementAdvisory('network', env('aws-vpc-cni', 'mixed'));
    expect(a?.severity).toBe('error');
    expect(isDismissible(a!)).toBe(false);
  });

  it('is honest rather than reassuring when enforcement is unknown', () => {
    const a = enforcementAdvisory('network', env('unknown', 'unknown'));
    expect(a?.severity).toBe('info');
    expect(a?.detail).toMatch(/could not establish/i);
    expect(isDismissible(a!)).toBe(true);
  });

  it('warns on a Cilium policy where Cilium is not the CNI', () => {
    const a = enforcementAdvisory('cilium', env('aws-vpc-cni', 'enforced'));
    expect(a?.severity).toBe('warning');
    expect(a?.title).toContain('aws-vpc-cni');
  });

  it('does not claim a Cilium mismatch when the CNI is unknown', () => {
    // No signal means behave as before, not guess.
    expect(enforcementAdvisory('cilium', env('unknown', 'unknown'))).toBeNull();
  });

  it('never tells the operator a standard policy works everywhere', () => {
    // Regression guard on the exact false-assurance text this replaced:
    // "A standard Network Policy works on any CNI." It does not — it
    // works where the CNI enforces it, which is the whole point.
    const types: PolicyType[] = ['network', 'cilium', 'seccomp'];
    for (const t of types) {
      for (const c of ['cilium', 'aws-vpc-cni', 'calico', 'flannel', 'unknown']) {
        for (const e of ['enforced', 'unenforced', 'mixed', 'unknown']) {
          const a = enforcementAdvisory(t, env(c, e));
          if (a) expect(a.detail).not.toMatch(/works on any CNI/i);
        }
      }
    }
  });
});
