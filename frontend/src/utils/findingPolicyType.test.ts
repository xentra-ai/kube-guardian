import { describe, expect, test } from 'vitest';
import { ALL_FINDING_KINDS, COMPUTE_FINDING_KINDS, findingAction, policyTypeForFinding } from './findingPolicyType';

describe('policyTypeForFinding', () => {
  test('sensitive syscalls → seccomp regardless of CNI', () => {
    expect(policyTypeForFinding('sensitive-syscalls')).toBe('seccomp');
    expect(policyTypeForFinding('sensitive-syscalls', 'cilium')).toBe('seccomp');
  });
  test('network findings → NetworkPolicy by default (unknown / non-cilium CNI)', () => {
    expect(policyTypeForFinding('denied-traffic')).toBe('network');
    expect(policyTypeForFinding('egress-fanout', 'unknown')).toBe('network');
    expect(policyTypeForFinding('would-deny', 'calico')).toBe('network');
  });
  test('network findings → Cilium tab when the cluster CNI is cilium', () => {
    expect(policyTypeForFinding('denied-traffic', 'cilium')).toBe('cilium');
    expect(policyTypeForFinding('egress-fanout', 'cilium')).toBe('cilium');
    expect(policyTypeForFinding('would-deny', 'cilium')).toBe('cilium');
  });
});

describe('findingAction (design D7)', () => {
  test('the four original kinds open the Policy Builder', () => {
    expect(findingAction('denied-traffic')).toBe('policy');
    expect(findingAction('sensitive-syscalls')).toBe('policy');
    expect(findingAction('egress-fanout')).toBe('policy');
    expect(findingAction('would-deny')).toBe('policy');
  });
  test('every compute kind is a resources action — there is no policy to build', () => {
    expect(COMPUTE_FINDING_KINDS).toEqual(['noisy-neighbor', 'cpu-throttled', 'cpu-contended', 'memory-pressure', 'memory-limit-thrash']);
    for (const kind of COMPUTE_FINDING_KINDS) expect(findingAction(kind)).toBe('resources');
  });
  test('ALL_FINDING_KINDS is exhaustive and each kind has exactly one action', () => {
    expect(ALL_FINDING_KINDS).toHaveLength(9);
    for (const kind of ALL_FINDING_KINDS) expect(['policy', 'resources']).toContain(findingAction(kind));
  });
});
