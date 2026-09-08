import { describe, it, expect } from 'vitest';
import { buildSeccompProfile, validateSeccompProfile } from './seccompProfileGenerator';

// Parity with the advisor's k8s.ValidateProfile and the llm-bridge assistant's
// validateSeccompProfile: an unrecognized CPU arch must be rejected rather than
// yielding a silently-unusable profile. buildSeccompProfile stays pure (the G2
// fixtures assert its output); validation is a separate, explicit step.
describe('validateSeccompProfile', () => {
  it('accepts a well-formed profile', () => {
    const p = buildSeccompProfile(['read', 'write'], 'x86_64');
    expect(() => validateSeccompProfile(p)).not.toThrow();
    expect(p.architectures).toEqual(['SCMP_ARCH_X86_64']);
  });

  it('rejects an unrecognized architecture (empty architectures)', () => {
    const p = buildSeccompProfile(['read'], 'ppc64le');
    expect(p.architectures).toEqual([]); // build stays pure
    expect(() => validateSeccompProfile(p)).toThrow(/unrecognized architecture/);
  });

  it('rejects a missing default action', () => {
    expect(() =>
      validateSeccompProfile({ defaultAction: '', architectures: ['SCMP_ARCH_X86_64'], syscalls: [{ names: ['read'], action: 'SCMP_ACT_ALLOW' }] }),
    ).toThrow(/default action is required/);
  });

  it('rejects no syscall rules', () => {
    expect(() =>
      validateSeccompProfile({ defaultAction: 'SCMP_ACT_ERRNO', architectures: ['SCMP_ARCH_X86_64'], syscalls: [] }),
    ).toThrow(/at least one syscall rule/);
  });

  // The rules-array check above counts one, not zero, for the profile that
  // actually matters: a single rule with an empty `names` list. Verified
  // against a container runtime — that profile denies every syscall and the
  // container never starts, because the filter is installed before execve.
  it('rejects a denying default with an allow rule that names nothing', () => {
    expect(() => validateSeccompProfile(buildSeccompProfile([], 'x86_64'))).toThrow(
      /no rule allows any syscall/,
    );
  });

  it('rejects a denying default when every allow rule is empty', () => {
    expect(() =>
      validateSeccompProfile({
        defaultAction: 'SCMP_ACT_ERRNO',
        architectures: ['SCMP_ARCH_X86_64'],
        syscalls: [
          { names: [], action: 'SCMP_ACT_ALLOW' },
          { names: ['ptrace'], action: 'SCMP_ACT_KILL' },
        ],
      }),
    ).toThrow(/no rule allows any syscall/);
  });

  it('accepts a denying default as soon as one rule allows something', () => {
    expect(() => validateSeccompProfile(buildSeccompProfile(['read'], 'x86_64'))).not.toThrow();
  });

  // A permissive default with an empty rule is a no-op, not a trap: the
  // container still runs. Only a denying default makes an empty allow list
  // fatal, so the check must not fire here.
  it('accepts a permissive default with an empty rule', () => {
    expect(() =>
      validateSeccompProfile({
        defaultAction: 'SCMP_ACT_ALLOW',
        architectures: ['SCMP_ARCH_X86_64'],
        syscalls: [{ names: [], action: 'SCMP_ACT_ERRNO' }],
      }),
    ).not.toThrow();
  });

  it('accepts an audit-only profile that allows nothing by name', () => {
    expect(() =>
      validateSeccompProfile({
        defaultAction: 'SCMP_ACT_LOG',
        architectures: ['SCMP_ARCH_X86_64'],
        syscalls: [{ names: [], action: 'SCMP_ACT_ALLOW' }],
      }),
    ).not.toThrow();
  });
});
