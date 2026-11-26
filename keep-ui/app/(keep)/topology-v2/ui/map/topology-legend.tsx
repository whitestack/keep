import { Panel } from "@xyflow/react";
import {
  RESOURCE_STATES,
  type ResourceState,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import { resourceStateIcons } from "@/app/(keep)/topology-v2/ui/map/resource-status-badge";

export function TopologyLegend() {
  return (
    <Panel position="bottom-right">
      <details
        open
        className="max-w-[280px] rounded-lg border border-slate-200 bg-white/95 p-3 text-xs text-slate-700 shadow-sm dark:border-slate-700 dark:bg-slate-900/95 dark:text-slate-200"
      >
        <summary className="cursor-pointer font-semibold">
          Resource states
        </summary>
        <ul
          className="mt-2 grid grid-cols-2 gap-x-3 gap-y-2"
          aria-label="Resource state legend"
        >
          {(Object.keys(RESOURCE_STATES) as ResourceState[]).map((state) => {
            const Icon = resourceStateIcons[state];
            return (
              <li key={state} className="flex items-center gap-1.5">
                <Icon
                  className="h-4 w-4 shrink-0"
                  style={{ color: RESOURCE_STATES[state].color }}
                  aria-hidden="true"
                />
                {RESOURCE_STATES[state].label}
              </li>
            );
          })}
        </ul>
        <p className="mt-3 border-t border-slate-200 pt-2 dark:border-slate-700">
          Connection colors are inferred from the connected resources.
        </p>
        <p className="mt-1">States reflect the last provider pull.</p>
      </details>
    </Panel>
  );
}
