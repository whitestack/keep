import {
  formatVmPercent,
  formatVmRam,
  type VmMetrics,
} from "@/app/(keep)/topology-v2/lib/vm-metrics";

export function VmMetricsSummary({ metrics }: { metrics: VmMetrics }) {
  return (
    <dl
      className="grid grid-cols-2 gap-3 border-t border-slate-200 pt-1.5 text-xs dark:border-slate-700"
      aria-label="VM utilization at last pull"
    >
      <div
        className="flex items-center justify-between gap-1"
        title={`CPU usage across assigned vCPUs${metrics.window ? `, average over ${metrics.window}` : ""}. Snapshot at last pull.`}
      >
        <dt className="text-slate-500 dark:text-slate-400">CPU</dt>
        <dd className="font-medium tabular-nums">
          {formatVmPercent(metrics.cpuPercent)}
        </dd>
      </div>
      <div
        className="flex items-center justify-between gap-1"
        title="Guest RAM usage at last pull"
      >
        <dt className="text-slate-500 dark:text-slate-400">RAM</dt>
        <dd className="font-medium tabular-nums">
          {formatVmPercent(metrics.ramPercent)}
        </dd>
      </div>
    </dl>
  );
}

export function VmMetricsDetails({ metrics }: { metrics: VmMetrics }) {
  return (
    <div className="border-t border-border px-4 py-3 text-xs">
      <dl className="grid grid-cols-2 gap-2">
        <dt className="text-muted-foreground">Assigned vCPUs</dt>
        <dd className="text-right font-medium">{metrics.vcpus ?? "No data"}</dd>
        <dt className="text-muted-foreground">Maximum assigned RAM</dt>
        <dd className="text-right font-medium">
          {formatVmRam(metrics.ramCapacityBytes)}
        </dd>
      </dl>
      <dl className="mt-3 grid grid-cols-2 gap-3 border-t border-border pt-3">
        <div>
          <dt className="font-medium">CPU usage (%)</dt>
          <dd className="mt-1 text-muted-foreground">
            {metrics.window === "5m"
              ? "5-minute average"
              : metrics.window
                ? `${metrics.window} average`
                : "No data"}
          </dd>
        </div>
        <div>
          <dt className="font-medium">RAM usage (%)</dt>
          <dd className="mt-1 text-muted-foreground">Latest measurement</dd>
        </div>
      </dl>
      {metrics.updatedAt && (
        <p className="mt-3 text-muted-foreground">
          Queried at ·{" "}
          <time dateTime={metrics.updatedAt}>
            {new Date(metrics.updatedAt).toLocaleString("en-US", {
              month: "short",
              day: "numeric",
              hour: "numeric",
              minute: "2-digit",
            })}
          </time>
        </p>
      )}
    </div>
  );
}
