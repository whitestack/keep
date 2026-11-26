import { formatBitrate } from "@/app/(keep)/topology-v2/lib/port-traffic";
import type { ResourceConnectionData } from "@/app/(keep)/topology-v2/ui/map/resource-status-edge";
import { RESOURCE_STATES } from "@/app/(keep)/topology-v2/lib/resource-state";

export function ConnectionTooltip({ data }: { data?: ResourceConnectionData }) {
  if (!data) return <span>Connection condition unknown</span>;
  const traffic = data.traffic;
  return (
    <div className="flex max-w-72 flex-col gap-2">
      <p className="break-words font-medium">
        {data.sourceName} → {data.targetName}
      </p>
      <p className="text-xs">
        Inferred condition: {RESOURCE_STATES[data.state].label}
      </p>
      {traffic && (
        <div className="flex flex-col gap-1 border-t border-current/20 pt-2">
          <p className="text-xs font-medium">Virtual interface traffic</p>
          <p className="break-words text-xs">{traffic.portName}</p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
            <dt>Received</dt>
            <dd className="text-right tabular-nums">
              {formatBitrate(traffic.receivedBps)}
            </dd>
            <dt>Transmitted</dt>
            <dd className="text-right tabular-nums">
              {formatBitrate(traffic.transmittedBps)}
            </dd>
          </dl>
          {traffic.window && (
            <p className="text-xs">Average over {traffic.window}</p>
          )}
          {traffic.updatedAt && (
            <p className="text-xs">
              Last updated:{" "}
              <time dateTime={traffic.updatedAt}>
                {new Date(traffic.updatedAt).toLocaleString()}
              </time>
            </p>
          )}
        </div>
      )}
      <p className="text-xs">
        Connection color is inferred from resource states, not traffic usage.
      </p>
    </div>
  );
}
