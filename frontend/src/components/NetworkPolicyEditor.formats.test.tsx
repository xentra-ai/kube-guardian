// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { PodInfo, PodNodeData } from '../types';
import { UNKNOWN_CLUSTER_ENVIRONMENT } from '../types';
import { quoteYamlValue } from '../utils/networkPolicyGenerator';

// The network tab offers the same kind of format switch as the seccomp tab:
// an AuditNetworkPolicy (kguardian CR, nothing dropped), the plain
// NetworkPolicy, or a CiliumNetworkPolicy where the CNI can read one.

let cni = 'unknown';

const podRecord = (p: Partial<PodInfo> & { pod_name: string; pod_ip: string }): PodInfo => ({
  pod_namespace: 'default', time_stamp: '2026-09-03T00:00:00', node_name: 'worker-0', is_dead: false, ...p,
});
const api = podRecord({ pod_name: 'api-0', pod_ip: '10.0.0.9', pod_namespace: 'prod', workload_selector_labels: { app: 'api' } });

vi.mock('../services/api', () => {
  const apiClient = {
    getServiceByIP: vi.fn().mockResolvedValue(null),
    getPodDetailsByIP: vi.fn(async (ip: string) => (ip === '10.0.0.9' ? api : null)),
    getPodDetailsByName: vi.fn(async () => null),
    getClusterEnvironment: vi.fn(async () => ({ ...UNKNOWN_CLUSTER_ENVIRONMENT, cni })),
  };
  return { apiClient, default: apiClient };
});
vi.mock('../services/seccompApi', () => ({
  seccompApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue(null) }),
}));

import NetworkPolicyEditor from './NetworkPolicyEditor';

const web = podRecord({ pod_name: 'web', pod_ip: '10.0.0.1', pod_namespace: 'prod', workload_selector_labels: { app: 'web' } });
const target: PodNodeData = {
  id: 'web', label: 'web', pod: web, pods: [web], isExpanded: false,
  traffic: [{ traffic_type: 'EGRESS', traffic_in_out_ip: '10.0.0.9', traffic_in_out_port: '8080', ip_protocol: 'TCP' }],
} as PodNodeData;

const yamlHeader = () => {
  const pre = document.querySelector('pre');
  return (pre?.textContent ?? '').split('\n').slice(0, 2);
};
const header = (apiVersion: string, kind: string) => [`apiVersion: ${quoteYamlValue(apiVersion)}`, `kind: ${quoteYamlValue(kind)}`];

afterEach(() => {
  cleanup();
  cni = 'unknown';
});

test('the network tab offers Audit, NetworkPolicy and Cilium; Audit only swaps the header lines', async () => {
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));
  const group = screen.getByRole('radiogroup', { name: 'Network policy format' });
  const radios = group.querySelectorAll('[role=radio]');
  expect([...radios].map((r) => r.textContent?.trim())).toEqual(['Audit (kguardian CR)', 'NetworkPolicy', 'CiliumNetworkPolicy']);
  expect(yamlHeader()).toEqual(header('networking.k8s.io/v1', 'NetworkPolicy'));

  fireEvent.click(screen.getByRole('radio', { name: /Audit/ }));
  expect(yamlHeader()).toEqual(header('kguardian.dev/v1alpha1', 'AuditNetworkPolicy'));
  expect(screen.getByText('Audit Network Policy Builder')).toBeTruthy();
  expect(screen.getByText('Save Audit Policy')).toBeTruthy();

  fireEvent.click(screen.getByRole('radio', { name: 'NetworkPolicy' }));
  expect(yamlHeader()).toEqual(header('networking.k8s.io/v1', 'NetworkPolicy'));
});

test('Cilium is offered but disabled, with the reason, when the CNI is known not to be Cilium', async () => {
  cni = 'calico';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} initialPolicyType="network" />);
  await screen.findByText((_, el) => el?.tagName === 'PRE' && !!el.textContent?.includes('kind: NetworkPolicy'));
  // The environment lands asynchronously; wait for the disabled state.
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect((cilium as HTMLButtonElement).disabled).toBe(true));
  expect(cilium.getAttribute('title')).toMatch(/calico/);
});

test('on a Cilium cluster the Cilium format is selectable and the tab strip is Network / Seccomp', async () => {
  cni = 'cilium';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} />);
  const tabs = await screen.findAllByRole('tab');
  expect(tabs.map((t) => t.textContent?.trim())).toEqual(['Network Policy', 'Seccomp Profile']);
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect(cilium.getAttribute('aria-checked')).toBe('true'));
  expect(screen.getByText('Cilium Policy Builder')).toBeTruthy();
});

test('switching to Seccomp and back to Network restores the Cilium format', async () => {
  cni = 'cilium';
  render(<NetworkPolicyEditor isOpen onClose={() => {}} pod={target} />);
  const cilium = await screen.findByRole('radio', { name: /CiliumNetworkPolicy/ });
  await vi.waitFor(() => expect(cilium.getAttribute('aria-checked')).toBe('true'));
  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp Profile' }));
  expect(screen.getByText('Seccomp Profile Builder')).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: 'Network Policy' }));
  expect(screen.getByText('Cilium Policy Builder')).toBeTruthy();
});
