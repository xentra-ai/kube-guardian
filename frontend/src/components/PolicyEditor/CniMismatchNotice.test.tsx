// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PolicyAdvisoryNotice } from './CniMismatchNotice';
import { enforcementAdvisory } from '../../utils/cniPolicySupport';

afterEach(cleanup);

// The notice backs CNI-aligned policy generation. It covers two
// independent questions: whether the CNI understands the policy kind on
// screen, and whether it enforces policy at all. The second used to be
// missing, and its absence let the console tell an operator a policy was
// fine while the CNI silently ignored it.

const advisory = (type: Parameters<typeof enforcementAdvisory>[0], cni: string, enf: string) =>
  enforcementAdvisory(type, { cni, policy_enforcement: enf })!;

test('a Cilium policy on a non-Cilium CNI names the CNI and both failure modes', () => {
  render(<PolicyAdvisoryNotice advisory={advisory('cilium', 'calico', 'enforced')} />);
  const text = screen.getByRole('note').textContent ?? '';
  expect(text).toContain('calico');
  expect(text).toContain('CRD is likely absent');
  expect(text).toContain('read by nobody');
});

test('a warning is dismissible without disabling export', () => {
  render(<PolicyAdvisoryNotice advisory={advisory('cilium', 'flannel', 'unknown')} />);
  fireEvent.click(screen.getByLabelText('Dismiss policy notice'));
  expect(screen.queryByRole('note')).toBeNull();
});

test('an inert policy is an alert and CANNOT be dismissed', () => {
  // The operator opened this editor to restrict a workload. Letting
  // them wave away the one message saying the restriction will not
  // happen is how a tool ends up trusted while doing nothing.
  render(<PolicyAdvisoryNotice advisory={advisory('network', 'aws-vpc-cni', 'unenforced')} />);
  expect(screen.getByRole('alert')).toBeTruthy();
  expect(screen.queryByLabelText('Dismiss policy notice')).toBeNull();
});

test('the inert message says the object will apply and restrict nothing', () => {
  render(<PolicyAdvisoryNotice advisory={advisory('network', 'aws-vpc-cni', 'unenforced')} />);
  const text = screen.getByRole('alert').textContent ?? '';
  expect(text).toMatch(/no traffic will be restricted/i);
  expect(text).toContain('--enable-network-policy');
});

test('a split fleet is an alert too, since placement decides the outcome', () => {
  render(<PolicyAdvisoryNotice advisory={advisory('network', 'aws-vpc-cni', 'mixed')} />);
  expect(screen.getByRole('alert').textContent).toMatch(/one node and not on another/i);
});

test('unknown enforcement is stated honestly rather than reassuringly', () => {
  render(<PolicyAdvisoryNotice advisory={advisory('network', 'unknown', 'unknown')} />);
  const text = screen.getByRole('note').textContent ?? '';
  expect(text).toMatch(/could not establish/i);
  expect(text).not.toMatch(/works on any CNI/i);
});
