import { describe, expect, test } from 'vitest';
import { toAuditNetworkPolicy } from './auditNetworkPolicy';
import { policyToYAML, quoteYamlValue } from './networkPolicyGenerator';
import type { NetworkPolicy } from '../types/networkPolicy';

const base: NetworkPolicy = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'NetworkPolicy',
  metadata: { name: 'payments-isolation', namespace: 'prod' },
  spec: {
    podSelector: { matchLabels: { app: 'payments' } },
    policyTypes: ['Ingress', 'Egress'],
    ingress: [],
    egress: [],
  },
};

describe('toAuditNetworkPolicy', () => {
  test('only the apiVersion and kind change; name and spec are identical', () => {
    const audit = toAuditNetworkPolicy(base);
    expect(audit.apiVersion).toBe('kguardian.dev/v1alpha1');
    expect(audit.kind).toBe('AuditNetworkPolicy');
    expect(audit.metadata).toEqual(base.metadata);
    expect(audit.spec).toEqual(base.spec);
    expect(base.kind).toBe('NetworkPolicy'); // input untouched
  });

  test('the rendered YAML differs from the NetworkPolicy only in its two header lines', () => {
    const a = policyToYAML(toAuditNetworkPolicy(base)).split('\n');
    const n = policyToYAML(base).split('\n');
    expect(a.length).toBe(n.length);
    const diff = a.map((l, i) => [l, n[i]]).filter(([x, y]) => x !== y);
    expect(diff).toEqual([
      [`apiVersion: ${quoteYamlValue('kguardian.dev/v1alpha1')}`, `apiVersion: ${quoteYamlValue('networking.k8s.io/v1')}`],
      [`kind: ${quoteYamlValue('AuditNetworkPolicy')}`, `kind: ${quoteYamlValue('NetworkPolicy')}`],
    ]);
  });
});
