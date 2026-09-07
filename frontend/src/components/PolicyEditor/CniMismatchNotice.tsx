import React, { useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { isDismissible, type PolicyAdvisory } from '../../utils/cniPolicySupport';

interface PolicyAdvisoryNoticeProps {
  advisory: PolicyAdvisory;
}

/**
 * Notice shown above the policy body when the cluster cannot enforce
 * the kind of policy on screen.
 *
 * Two changes from the CNI-only notice this replaces, both of which
 * matter more than they look:
 *
 * It no longer claims "a standard Network Policy works on any CNI".
 * That was false. A NetworkPolicy is enforced only where the CNI
 * enforces policy, and AWS VPC CNI — the default on EKS — ships with
 * enforcement OFF, in which case it accepts the object and silently
 * ignores it. Telling an operator their policy "works" there is the
 * worst available answer for a tool whose promise is that
 * observed-absence means safe-to-deny.
 *
 * And an `error` advisory is NOT dismissible. The operator opened this
 * editor to restrict a workload; letting them wave away the single
 * message saying the restriction will not happen defeats the point.
 * Lesser advisories stay dismissible so the console does not nag.
 */
export const PolicyAdvisoryNotice: React.FC<PolicyAdvisoryNoticeProps> = ({ advisory }) => {
  const [dismissed, setDismissed] = useState(false);
  const dismissible = isDismissible(advisory);
  if (dismissed && dismissible) return null;

  const tone =
    advisory.severity === 'error'
      ? 'bg-hubble-error/10 border-hubble-error/30 text-hubble-error'
      : advisory.severity === 'warning'
        ? 'bg-hubble-warning/10 border-hubble-warning/30 text-hubble-warning'
        : 'bg-surface-raised border-border text-tertiary';

  return (
    <div
      role={advisory.severity === 'error' ? 'alert' : 'note'}
      className={`flex items-start gap-2 px-4 py-2.5 border-b text-xs ${tone}`}
    >
      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
      <p className="flex-1 text-secondary">
        <span className="font-medium text-primary">{advisory.title}.</span> {advisory.detail}
      </p>
      {dismissible && (
        <button
          onClick={() => setDismissed(true)}
          aria-label="Dismiss policy notice"
          className="text-tertiary hover:text-primary transition-colors"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
};
