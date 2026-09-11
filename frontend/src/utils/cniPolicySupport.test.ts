import { describe, it, expect } from 'vitest';
import { ALL_FINDING_KINDS, findingAction, policyTypeForFinding } from './findingPolicyType';
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

describe('one rule, one place', () => {
  // The regression this guards is one I introduced and nearly shipped:
  // findingPolicyType already encoded "cilium gets a CiliumNetworkPolicy,
  // everything else gets a NetworkPolicy", and adding a second copy in
  // recommendedPolicyType meant a CNI added to one would silently not be
  // added to the other. They must agree by construction, not by memory.
  it('findingPolicyType agrees with recommendedPolicyType for every CNI', () => {
    for (const cni of ['cilium', 'aws-vpc-cni', 'calico', 'flannel', 'antrea', 'weave', 'unknown']) {
      expect(policyTypeForFinding('denied-traffic', cni)).toBe(recommendedPolicyType(cni));
      expect(policyTypeForFinding('would-deny', cni)).toBe(recommendedPolicyType(cni));
    }
  });

  it('still routes a syscall finding to seccomp regardless of CNI', () => {
    for (const cni of ['cilium', 'aws-vpc-cni', 'unknown']) {
      expect(policyTypeForFinding('sensitive-syscalls', cni)).toBe('seccomp');
    }
  });

  it('every policy-kind × CNI maps to a policy type the CNI can enforce', () => {
    // The compute kinds (noisy-neighbor, cpu-throttled, cpu-contended,
    // memory-pressure, memory-limit-thrash) are EXCLUDED on purpose: they are
    // `resources` findings (design D7) with no policy to build, and the App
    // never calls policyTypeForFinding for them. Iterating them here would
    // assert a mapping that must not exist.
    const policyKinds = ALL_FINDING_KINDS.filter((k) => findingAction(k) === 'policy');
    expect(policyKinds).toEqual(['denied-traffic', 'sensitive-syscalls', 'egress-fanout', 'would-deny']);
    for (const kind of policyKinds) {
      for (const cni of ['cilium', 'aws-vpc-cni', 'calico', 'flannel', 'antrea', 'weave', 'unknown']) {
        const expected = kind === 'sensitive-syscalls' ? 'seccomp' : recommendedPolicyType(cni);
        expect(policyTypeForFinding(kind, cni)).toBe(expected);
      }
    }
  });
});
