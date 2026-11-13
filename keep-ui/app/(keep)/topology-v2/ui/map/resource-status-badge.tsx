import {
  CircleAlert,
  CircleCheck,
  CircleHelp,
  CirclePause,
  CircleX,
} from "lucide-react";
import { clsx } from "clsx";
import type {
  ResourceState,
  ResourceStatus,
} from "@/app/(keep)/topology-v2/lib/resource-state";

export const resourceStateIcons = {
  healthy: CircleCheck,
  warning: CircleAlert,
  critical: CircleX,
  stopped: CirclePause,
  unknown: CircleHelp,
};

const badgeStyles: Record<ResourceState, string> = {
  healthy:
    "bg-emerald-50 text-emerald-800 ring-emerald-200 dark:bg-emerald-950 dark:text-emerald-200 dark:ring-emerald-800",
  warning:
    "bg-yellow-50 text-yellow-800 ring-yellow-200 dark:bg-yellow-950 dark:text-yellow-200 dark:ring-yellow-800",
  critical:
    "bg-red-50 text-red-800 ring-red-200 dark:bg-red-950 dark:text-red-200 dark:ring-red-800",
  stopped:
    "bg-blue-50 text-blue-800 ring-blue-200 dark:bg-blue-950 dark:text-blue-200 dark:ring-blue-800",
  unknown:
    "bg-slate-100 text-slate-600 ring-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-600",
};

export function ResourceStatusBadge({
  status,
  title,
}: {
  status: ResourceStatus;
  title?: string;
}) {
  const Icon = resourceStateIcons[status.state];
  return (
    <span
      className={clsx(
        "inline-flex w-fit shrink-0 items-center gap-1.5 rounded-full px-2 py-1 text-xs font-medium ring-1 ring-inset",
        badgeStyles[status.state]
      )}
      aria-label={`Resource status: ${status.label}`}
      title={title}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {status.label}
    </span>
  );
}
