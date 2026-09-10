import { useEffect, useMemo, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Radar,
  Terminal,
  ArrowUpRight,
  FileCode,
  ChevronRight,
  Cpu,
  ExternalLink,
} from 'lucide-react';
import type { PodNodeData, AuditVerdict } from '../types';
import type { ComputeFinding, ComputeFindingKind } from '../types/compute';
import { findingAction, type FindingKind } from '../utils/findingPolicyType';
import { COMPUTE_KIND_LABEL } from '../utils/compute';
import api from '../services/api';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';

interface FindingsViewProps {
  pods: PodNodeData[];
  namespace: string;
  onSelectPod: (pod: PodNodeData) => void;
  /** Opens the Policy Builder on the tab relevant to the finding kind. */
  onBuildPolicy: (pod: PodNodeData, kind: FindingKind) => void;
  onOpenAudit: () => void;
  /** Broker-computed compute findings for the namespace (hooks/useComputeData). */
  computeFindings?: ComputeFinding[];
  /** False when no node reports compute — the section is then not offered. */
  computeEnabled?: boolean;
  /** "View workload" for a `resources` finding: jump to the pod on the map. */
  onViewWorkload?: (namespace: string, podName: string) => void;
}

type Severity = 'critical' | 'high' | 'medium';

/**
 * Syscalls that are meaningful runtime-security signals — container-escape,
 * privilege, kernel-tampering, and host-visibility calls. A workload issuing
 * these is worth a human's attention; the map elsewhere shows *all* syscalls,
 * this map assigns the ones that matter a severity.
 */
const DANGEROUS_SYSCALLS: Record<string, Severity> = {
  bpf: 'critical',
  kexec_load: 'critical',
  init_module: 'critical',
  finit_module: 'critical',
  delete_module: 'critical',
  reboot: 'critical',
  ptrace: 'high',
  mount: 'high',
  unshare: 'high',
  setns: 'high',
  pivot_root: 'high',
  process_vm_writev: 'high',
  swapon: 'high',
  swapoff: 'high',
  umount2: 'medium',
  chroot: 'medium',
  keyctl: 'medium',
  add_key: 'medium',
  request_key: 'medium',
  perf_event_open: 'medium',
  process_vm_readv: 'medium',
  syslog: 'medium',
  acct: 'medium',
  quotactl: 'medium',
  settimeofday: 'medium',
  clock_settime: 'medium',
  mknod: 'medium',
};

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1 };

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'bg-hubble-error/15 text-hubble-error border-hubble-error/30',
  high: 'bg-hubble-warning/15 text-hubble-warning border-hubble-warning/30',
  medium: 'bg-hubble-accent/15 text-hubble-accent border-hubble-accent/30',
};

// A workload reaching this many distinct destinations on egress is a fan-out
// worth surfacing (data exfil / peer-to-peer / crypto). Not an alarm — a signal.
const EGRESS_FANOUT_THRESHOLD = 10;

interface SyscallFinding {
  pod: PodNodeData;
  worst: Severity;
  calls: Array<{ name: string; severity: Severity }>;
}

interface DropFinding {
  pod: PodNodeData;
  drops: number;
}

interface FanoutFinding {
  pod: PodNodeData;
  peers: number;
}

function podLabel(pod: PodNodeData): string {
  return pod.label || pod.pod.pod_identity || pod.pod.pod_name;
}

/**
 * Triage home. Turns the raw graph into a ranked, human-first "what should I
 * look at" surface — blocked connections, sensitive syscalls, and egress fan-out —
 * computed entirely from data already loaded for the namespace, plus a
 * would-deny summary pulled from the audit evaluator. No invented scores: each
 * section is a concrete, explainable signal that links back into the map.
 */
export function FindingsView({
  pods,
  namespace,
  onSelectPod,
  onBuildPolicy,
  onOpenAudit,
  computeFindings = [],
  computeEnabled = false,
  onViewWorkload,
}: FindingsViewProps) {
  const workloads = useMemo(() => pods.filter((p) => !p.isExternal), [pods]);

  // Compute findings (design D7) come from the broker, already ranked by
  // severity there; a node filter narrows them because a noisy neighbour is
  // a per-node problem.
  const [nodeFilter, setNodeFilter] = useState<string>('all');
  const computeNodes = useMemo(
    () => [...new Set(computeFindings.map((f) => f.victim.node))].sort(),
    [computeFindings],
  );
  const filteredCompute = useMemo(() => {
    const rows = nodeFilter === 'all' ? computeFindings : computeFindings.filter((f) => f.victim.node === nodeFilter);
    return [...rows].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.victim.pod_name.localeCompare(b.victim.pod_name),
    );
  }, [computeFindings, nodeFilter]);
  const computeWorst = filteredCompute[0]?.severity;

  const dropFindings = useMemo<DropFinding[]>(() => {
    return workloads
      .map((pod) => ({ pod, drops: (pod.traffic ?? []).filter((t) => t.decision === 'DROP').length }))
      .filter((f) => f.drops > 0)
      .sort((a, b) => b.drops - a.drops);
  }, [workloads]);

  const syscallFindings = useMemo<SyscallFinding[]>(() => {
    return workloads
      .map((pod) => {
        const seen = new Map<string, Severity>();
        (pod.syscalls ?? []).forEach((record) => {
          record.syscalls.split(',').forEach((raw) => {
            const name = raw.trim();
            const severity = DANGEROUS_SYSCALLS[name];
            if (severity) seen.set(name, severity);
          });
        });
        const calls = [...seen.entries()]
          .map(([name, severity]) => ({ name, severity }))
          // Name tiebreak: equal severities otherwise keep Map insertion
          // order, which is capture order — inconsistent across refreshes.
          .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.name.localeCompare(b.name));
        const worst = calls.reduce<Severity | null>(
          (acc, c) => (acc === null || SEVERITY_RANK[c.severity] > SEVERITY_RANK[acc] ? c.severity : acc),
          null,
        );
        return calls.length > 0 && worst ? { pod, worst, calls } : null;
      })
      .filter((f): f is SyscallFinding => f !== null)
      // Pod-label tiebreak for the same reason as the per-call sort above.
      .sort((a, b) =>
        SEVERITY_RANK[b.worst] - SEVERITY_RANK[a.worst]
        || b.calls.length - a.calls.length
        || podLabel(a.pod).localeCompare(podLabel(b.pod)));
  }, [workloads]);

  const fanoutFindings = useMemo<FanoutFinding[]>(() => {
    return workloads
      .map((pod) => {
        const peers = new Set<string>();
        (pod.traffic ?? []).forEach((t) => {
          if (t.traffic_type?.toLowerCase() === 'egress' && t.traffic_in_out_ip) {
            peers.add(t.traffic_in_out_ip);
          }
        });
        return { pod, peers: peers.size };
      })
      .filter((f) => f.peers >= EGRESS_FANOUT_THRESHOLD)
      .sort((a, b) => b.peers - a.peers);
  }, [workloads]);

  // Would-deny summary from the audit evaluator, namespace-scoped.
  const [auditLoading, setAuditLoading] = useState(true);
  const [wouldDeny, setWouldDeny] = useState<AuditVerdict[]>([]);
  useEffect(() => {
    let cancelled = false;
    /* eslint-disable-next-line react-hooks/set-state-in-effect */
    setAuditLoading(true);
    api
      .getAuditVerdicts({ namespace, verdict: 'WouldDeny', limit: 500 })
      .then((rows) => {
        if (!cancelled) setWouldDeny(rows);
      })
      .finally(() => {
        if (!cancelled) setAuditLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [namespace]);

  const topWouldDeny = useMemo(() => {
    const byPolicy = new Map<string, number>();
    wouldDeny.forEach((v) => {
      const key = v.policy_namespace ? `${v.policy_namespace}/${v.policy_name}` : v.policy_name;
      byPolicy.set(key, (byPolicy.get(key) ?? 0) + 1);
    });
    return [...byPolicy.entries()].map(([policy, count]) => ({ policy, count })).sort((a, b) => b.count - a.count);
  }, [wouldDeny]);

  const totalDrops = dropFindings.reduce((sum, f) => sum + f.drops, 0);
  const findingCount = dropFindings.length + syscallFindings.length + fanoutFindings.length + computeFindings.length;

  const stats = [
    { label: 'Workloads', value: workloads.length, icon: ShieldCheck, tone: 'text-hubble-accent' },
    { label: 'Blocked connections', value: totalDrops, icon: ShieldAlert, tone: totalDrops > 0 ? 'text-hubble-error' : 'text-secondary' },
    { label: 'Sensitive syscalls', value: syscallFindings.length, icon: Terminal, tone: syscallFindings.length > 0 ? 'text-hubble-warning' : 'text-secondary' },
    { label: 'Egress fan-out', value: fanoutFindings.length, icon: Radar, tone: fanoutFindings.length > 0 ? 'text-hubble-warning' : 'text-secondary' },
    ...(computeEnabled
      ? [{
          label: 'Compute',
          value: computeFindings.length,
          icon: Cpu,
          tone: computeWorst === 'critical' ? 'text-hubble-error' : computeFindings.length > 0 ? 'text-hubble-warning' : 'text-secondary',
        }]
      : []),
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-6 py-6 space-y-6">
        {/* Header */}
        <div>
          <h2 className="text-base font-semibold text-primary">Findings</h2>
          <p className="text-xs text-tertiary mt-0.5">
            Prioritized runtime-security signals for namespace{' '}
            <span className="text-secondary font-mono">{namespace}</span>. Each links back into the map.
          </p>
        </div>

        {/* Stat row */}
        <div className={`grid grid-cols-2 sm:grid-cols-4 gap-3 ${stats.length === 5 ? 'lg:grid-cols-5' : ''}`}>
          {stats.map((s) => {
            const Icon = s.icon;
            return (
              <div key={s.label} className="rounded-surface border border-hubble-border bg-hubble-card px-4 py-3">
                <div className="flex items-center gap-2 text-tertiary text-[11px] uppercase tracking-wide">
                  <Icon className={`w-3.5 h-3.5 ${s.tone}`} />
                  {s.label}
                </div>
                <div className={`mt-1 text-2xl font-semibold font-mono tabular-nums ${s.tone}`}>{s.value}</div>
              </div>
            );
          })}
        </div>

        {findingCount === 0 && !auditLoading && topWouldDeny.length === 0 ? (
          <div className="rounded-surface border border-hubble-border bg-hubble-card">
            <EmptyState
              icon={ShieldCheck}
              title="No standout findings"
              description={`No blocked connections, sensitive syscalls,${computeEnabled ? ' compute contention,' : ''} or unusual egress fan-out in this namespace. Keep an eye on the map for changes.`}
            />
          </div>
        ) : (
          <>
            {/* Would-deny */}
            <Section
              icon={ShieldAlert}
              tone="text-hubble-warning"
              title="Would-deny policies"
              hint="Flows your AuditNetworkPolicies would block if enforcing"
              action={
                <Button variant="ghost" size="sm" rightIcon={ArrowUpRight} onClick={onOpenAudit}>
                  Open audit
                </Button>
              }
            >
              {auditLoading ? (
                <div className="space-y-2 p-3">
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-8 w-2/3" />
                </div>
              ) : topWouldDeny.length === 0 ? (
                <p className="px-4 py-3 text-xs text-tertiary">No would-deny verdicts recorded for this namespace.</p>
              ) : (
                <ul className="divide-y divide-hubble-border">
                  {topWouldDeny.slice(0, 5).map((row) => (
                    <li key={row.policy} className="flex items-center justify-between gap-3 px-4 py-2.5">
                      <span className="font-mono text-xs text-secondary truncate">{row.policy}</span>
                      <span className="shrink-0 rounded-full bg-hubble-warning/15 text-hubble-warning text-xs font-medium px-2 py-0.5 tabular-nums">
                        {row.count} would-deny
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            {/* Denied traffic */}
            {dropFindings.length > 0 && (
              <Section icon={ShieldAlert} tone="text-hubble-error" title="Blocked connections" hint="Outbound connections that never completed. The cause is shown per flow: a policy is only one possibility">
                <ul className="divide-y divide-hubble-border">
                  {dropFindings.slice(0, 8).map(({ pod, drops }) => (
                    <FindingRow
                      key={pod.id}
                      title={podLabel(pod)}
                      badge={<Badge className="bg-hubble-error/15 text-hubble-error border-hubble-error/30">{drops} dropped</Badge>}
                      onView={() => onSelectPod(pod)}
                      onBuildPolicy={() => onBuildPolicy(pod, 'denied-traffic')}
                    />
                  ))}
                </ul>
              </Section>
            )}

            {/* Sensitive syscalls */}
            {syscallFindings.length > 0 && (
              <Section icon={Terminal} tone="text-hubble-warning" title="Sensitive syscalls" hint="Workloads issuing container-escape, privilege, or kernel-tampering calls">
                <ul className="divide-y divide-hubble-border">
                  {syscallFindings.slice(0, 8).map(({ pod, worst, calls }) => (
                    <FindingRow
                      key={pod.id}
                      title={podLabel(pod)}
                      badge={<Badge className={SEVERITY_CLASS[worst]}>{worst}</Badge>}
                      detail={
                        <div className="flex flex-wrap gap-1 mt-1">
                          {calls.slice(0, 8).map((c) => (
                            <span key={c.name} className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${SEVERITY_CLASS[c.severity]}`}>
                              {c.name}
                            </span>
                          ))}
                          {calls.length > 8 && <span className="text-[10px] text-tertiary self-center">+{calls.length - 8}</span>}
                        </div>
                      }
                      onView={() => onSelectPod(pod)}
                      onBuildPolicy={() => onBuildPolicy(pod, 'sensitive-syscalls')}
                    />
                  ))}
                </ul>
              </Section>
            )}

            {/* Compute: noisy neighbours, throttling, memory pressure (design D7) */}
            {computeFindings.length > 0 && (
              <Section
                icon={Cpu}
                tone={computeWorst === 'critical' ? 'text-hubble-error' : 'text-hubble-warning'}
                title="Compute contention"
                hint="Pods starved of CPU or memory, and the pod on the same node starving them. Fix is the workload's resources, not a policy"
                action={
                  computeNodes.length > 1 ? (
                    <label className="flex items-center gap-2 text-xs text-tertiary">
                      Node
                      <select
                        value={nodeFilter}
                        onChange={(e) => setNodeFilter(e.target.value)}
                        aria-label="Filter compute findings by node"
                        className="bg-hubble-dark border border-hubble-border rounded px-2 py-1 text-xs text-secondary focus:outline-none focus:border-hubble-accent"
                      >
                        <option value="all">All nodes</option>
                        {computeNodes.map((n) => (
                          <option key={n} value={n}>{n}</option>
                        ))}
                      </select>
                    </label>
                  ) : undefined
                }
              >
                {filteredCompute.length === 0 ? (
                  <p className="px-4 py-3 text-xs text-tertiary">No compute findings on this node.</p>
                ) : (
                  <ul className="divide-y divide-hubble-border">
                    {filteredCompute.slice(0, 12).map((f) => {
                      const key = `${f.kind}:${f.victim.container_uid}`;
                      const kind: ComputeFindingKind = f.kind;
                      const culpritLabel = f.culprit
                        ? f.culprit.kind === 'pod' && f.culprit.pod_name
                          ? `${f.culprit.namespace ?? ''}/${f.culprit.pod_name}`
                          : f.culprit.ref
                        : null;
                      // A `resources` finding links to the workload, never the Policy Builder
                      // (every compute kind is one; asserted rather than assumed).
                      const action = findingAction(kind);
                      return (
                        <FindingRow
                          key={key}
                          title={`${f.victim.pod_name} · ${f.victim.container}`}
                          badge={
                            <>
                              <Badge className={SEVERITY_CLASS[f.severity]}>{f.severity}</Badge>
                              <Badge className="bg-hubble-border/30 text-secondary border-hubble-border">{COMPUTE_KIND_LABEL[kind] ?? kind}</Badge>
                            </>
                          }
                          detail={
                            <div className="mt-1 text-xs text-tertiary">
                              <span>{f.message}</span>
                              <span className="ml-2 font-mono">node {f.victim.node}</span>
                              {culpritLabel && f.culprit && (
                                <span className="ml-2 font-mono text-hubble-error" title={`${Math.round(f.culprit.blame_share * 100)}% of the victim's wait`}>
                                  ← {culpritLabel} ({Math.round(f.culprit.blame_share * 100)}%)
                                </span>
                              )}
                            </div>
                          }
                          onView={() => onViewWorkload?.(f.victim.namespace, f.victim.pod_name)}
                          onViewWorkload={
                            action === 'resources' && onViewWorkload
                              ? () => {
                                  // The culprit is what an operator fixes (its requests); fall back to the victim.
                                  const target = f.culprit?.kind === 'pod' && f.culprit.pod_name
                                    ? { ns: f.culprit.namespace ?? f.victim.namespace, name: f.culprit.pod_name }
                                    : { ns: f.victim.namespace, name: f.victim.pod_name };
                                  onViewWorkload(target.ns, target.name);
                                }
                              : undefined
                          }
                        />
                      );
                    })}
                  </ul>
                )}
              </Section>
            )}

            {/* Egress fan-out */}
            {fanoutFindings.length > 0 && (
              <Section icon={Radar} tone="text-hubble-warning" title="High egress fan-out" hint={`Workloads reaching ${EGRESS_FANOUT_THRESHOLD}+ distinct destinations`}>
                <ul className="divide-y divide-hubble-border">
                  {fanoutFindings.slice(0, 8).map(({ pod, peers }) => (
                    <FindingRow
                      key={pod.id}
                      title={podLabel(pod)}
                      badge={<Badge className="bg-hubble-warning/15 text-hubble-warning border-hubble-warning/30">{peers} peers</Badge>}
                      onView={() => onSelectPod(pod)}
                      onBuildPolicy={() => onBuildPolicy(pod, 'egress-fanout')}
                    />
                  ))}
                </ul>
              </Section>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function Section({
  icon: Icon,
  tone,
  title,
  hint,
  action,
  children,
}: {
  icon: typeof ShieldAlert;
  tone: string;
  title: string;
  hint: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-surface border border-hubble-border bg-hubble-card overflow-hidden">
      <header className="flex items-center justify-between gap-3 px-4 py-3 border-b border-hubble-border">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className={`w-4 h-4 shrink-0 ${tone}`} />
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-primary">{title}</h3>
            <p className="text-[11px] text-tertiary truncate">{hint}</p>
          </div>
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function Badge({ className = '', children }: { className?: string; children: React.ReactNode }) {
  return (
    <span className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium tabular-nums ${className}`}>
      {children}
    </span>
  );
}

function FindingRow({
  title,
  badge,
  detail,
  onView,
  onBuildPolicy,
  onViewWorkload,
}: {
  title: string;
  badge: React.ReactNode;
  detail?: React.ReactNode;
  onView: () => void;
  /** `policy` findings: opens the Policy Builder. */
  onBuildPolicy?: () => void;
  /** `resources` findings (design D7): links to the workload instead of a policy. */
  onViewWorkload?: () => void;
}) {
  return (
    <li className="group flex items-start justify-between gap-3 px-4 py-3 hover:bg-hubble-hover/40 transition-colors">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-sm text-primary truncate">{title}</span>
          {badge}
        </div>
        {detail}
      </div>
      <div className="flex items-center gap-1 shrink-0 opacity-70 group-hover:opacity-100 transition-opacity">
        {onViewWorkload ? (
          <Button variant="ghost" size="sm" leftIcon={ExternalLink} onClick={onViewWorkload} title="Open the workload to fix its resources">
            View workload
          </Button>
        ) : onBuildPolicy ? (
          <Button variant="ghost" size="sm" leftIcon={FileCode} onClick={onBuildPolicy} title="Build a policy for this workload">
            Policy
          </Button>
        ) : null}
        <Button variant="ghost" size="sm" iconOnly rightIcon={ChevronRight} onClick={onView} aria-label="View in map" title="View in map" />
      </div>
    </li>
  );
}
