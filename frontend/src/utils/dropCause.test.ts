import { describe, it, expect } from 'vitest';
import { describeDrop, isDrop } from './dropCause';

describe('describeDrop', () => {
  it('states plainly that a policy is not the cause when none governs the pod', () => {
    // The reclassification this exists for. In a cluster with no
    // NetworkPolicies, every reported drop was labelled a policy denial
    // and sent the operator to audit policies that did not exist.
    const d = describeDrop('no-policy');
    expect(d.policyPlausible).toBe(false);
    expect(d.detail).toMatch(/cannot be the cause/i);
    // And points somewhere useful instead.
    expect(d.detail).toMatch(/security groups|routes|listening/i);
  });

  it('says "may have" rather than "did" when a policy governs the pod', () => {
    // A governing policy is a lead, not a confirmation: the probe sees
    // silence, never the denial.
    const d = describeDrop('policy-governs');
    expect(d.policyPlausible).toBe(true);
    expect(d.detail).toMatch(/may have denied/i);
    expect(d.detail).toMatch(/not the denial itself/i);
  });

  it('admits ignorance for an unclassified row', () => {
    for (const cause of ['unknown', null, undefined]) {
      const d = describeDrop(cause);
      expect(d.short).toBe('Connection failed');
      expect(d.detail).toMatch(/could not establish/i);
    }
  });

  it('treats a legacy row and an unknown classification identically', () => {
    // A row written before the column existed carries null, and that
    // means the same thing to a reader as an explicit "unknown".
    expect(describeDrop(null)).toEqual(describeDrop('unknown'));
  });

  it('never claims a policy denied the flow', () => {
    // Regression guard on the wording this replaced. The probe cannot
    // observe a denial, so no branch may assert one.
    for (const cause of ['no-policy', 'policy-governs', 'unknown', null]) {
      const d = describeDrop(cause, 4);
      expect(d.detail).not.toMatch(/denied by (a )?NetworkPolicy\b(?! selects)/i);
      expect(d.short).not.toMatch(/^Denied by policy$/i);
    }
  });

  it('surfaces the retry evidence when there is any', () => {
    // The probe always captured this and the controller logged it, but
    // it was never stored, so the operator could not tell 4 retries
    // (slow peer) from 40 (blackholed).
    expect(describeDrop('unknown', 4).detail).toMatch(/retried 4 times/);
    expect(describeDrop('no-policy', 12).detail).toMatch(/retried 12 times/);
  });

  it('omits the evidence clause when there is none', () => {
    for (const n of [undefined, null, 0]) {
      expect(describeDrop('unknown', n)).not.toHaveProperty('detail', expect.stringMatching(/retried/));
      expect(describeDrop('unknown', n).detail).not.toMatch(/retried/);
    }
  });
});

describe('isDrop', () => {
  it('recognises a dropped row and nothing else', () => {
    expect(isDrop('DROP')).toBe(true);
    expect(isDrop('ALLOW')).toBe(false);
    expect(isDrop(null)).toBe(false);
    expect(isDrop(undefined)).toBe(false);
  });
});
