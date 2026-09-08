/**
 * How to describe a dropped flow to an operator.
 *
 * The underlying signal is narrower than its name suggests.
 * `netpolicy_drop.bpf.c` reports a flow when an outbound TCP handshake
 * retransmits its SYN four times without reaching ESTABLISHED. That is
 * an honest observation of silence: the probe has no visibility into
 * why the handshake failed. It cannot distinguish a NetworkPolicy from
 * a security group, a route, a port nothing listens on that blackholes
 * rather than refuses, or a peer that is simply overloaded.
 *
 * Everything above it nonetheless said "policy": the file name, the
 * `decision: DROP` column, the "Network Policy Drop" log line, the
 * `denied-traffic` finding. And kguardian read no NetworkPolicy objects
 * at all, so it could not have known — in a cluster with none, every
 * reported policy drop was definitionally something else, and an
 * operator sent to audit their policies was sent nowhere.
 *
 * The broker now asks the evaluator which policies actually govern the
 * pod and stores the answer in `drop_cause`. This module turns that into
 * wording that claims only what is known.
 */

/** Values the broker stores in `drop_cause`. */
export type DropCause = 'no-policy' | 'policy-governs' | 'unknown';

export interface DropLabel {
  /** Short label for a badge or table cell. */
  short: string;
  /** One sentence an operator can act on. */
  detail: string;
  /**
   * Whether a NetworkPolicy is a plausible cause. Drives whether the UI
   * should offer to open the policy builder — sending someone to edit
   * policies that provably cannot be involved is the specific harm the
   * old wording caused.
   */
  policyPlausible: boolean;
}

/**
 * Describe a dropped flow.
 *
 * `cause` of null covers a row written before classification existed and
 * a row the evaluator could not classify. Both mean the same thing to a
 * reader — the cause is not known — so they share the wording, and
 * neither is allowed to imply a policy was or was not involved.
 */
export function describeDrop(cause: string | null | undefined, synRetries?: number | null): DropLabel {
  const evidence =
    typeof synRetries === 'number' && synRetries > 0
      ? ` The handshake was retried ${synRetries} times with no reply.`
      : '';

  switch (cause) {
    case 'no-policy':
      return {
        short: 'Blocked, not by policy',
        detail:
          'No NetworkPolicy governs this pod for egress, so a policy cannot be the cause. ' +
          'Look at security groups, routes, or whether anything is listening on that port.' +
          evidence,
        policyPlausible: false,
      };
    case 'policy-governs':
      return {
        short: 'Possibly denied by policy',
        detail:
          'A NetworkPolicy selects this pod for egress, so it may have denied this flow. ' +
          'kguardian observes only that the connection never completed, not the denial itself.' +
          evidence,
        policyPlausible: true,
      };
    default:
      return {
        short: 'Connection failed',
        detail:
          'The connection never completed. kguardian could not establish whether a NetworkPolicy ' +
          'was involved, so the cause is unknown.' +
          evidence,
        policyPlausible: true,
      };
  }
}

/**
 * True when the row is a dropped flow.
 *
 * Kept as a helper rather than comparing to `'DROP'` inline so the
 * stored value stays in one place: the column records that a handshake
 * did not complete, which is a weaker claim than its name, and callers
 * should be reading `describeDrop` for anything user-facing.
 */
export function isDrop(decision: string | null | undefined): boolean {
  return decision === 'DROP';
}
