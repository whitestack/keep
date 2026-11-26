
"use client";

import {
    Server,
    Monitor,
    ChevronDown,
    ChevronUp,
    Activity,
    Boxes,
    Plug
} from "lucide-react";
import { useMemo, useState } from "react";
import { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import {
    getResourceName,
    getResourceStatus,
    getResourceStatusDescription,
    parseDescription,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import { ResourceStatusBadge } from "@/app/(keep)/topology-v2/ui/map/resource-status-badge";
import { isTrafficField } from "@/app/(keep)/topology-v2/lib/port-traffic";
import {
    getVmMetrics,
    isVmMetricsField,
} from "@/app/(keep)/topology-v2/lib/vm-metrics";
import { VmMetricsDetails } from "@/app/(keep)/topology-v2/ui/map/vm-metrics";

type Props = {
    service: TopologyService;
};

function getIcon(type: string) {
    if (type === "port") return Plug;
    if (type === "instance") return Monitor;
    if (type === "hypervisor") return Server;
    return Boxes;
}

export default function ServiceDetailsCard({ service }: Props) {
    const [expanded, setExpanded] = useState(false);

    const fields = useMemo(
        () => parseDescription(service.description),
        [service.description]
    );

    const type = service.category?.trim().toLowerCase() || "resource";
    const Icon = getIcon(type);
    const status = getResourceStatus(service, fields);
    const name = getResourceName(service, fields);
    const vmMetrics = getVmMetrics(service);
    const attributes = Object.entries(fields).filter(
        ([key]) => !isTrafficField(key) && !isVmMetricsField(key)
    );

    return (
        <section className="w-[400px] max-w-[calc(100vw-32px)] overflow-hidden rounded-xl border border-border bg-tremor-background-muted text-card-foreground shadow-sm">
            {/* Header */}
            <div className="flex items-center gap-3 p-2">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
                    <Icon className="h-6 w-6" />
                </div>

                <div className="min-w-0 flex-1 items-center">
                    <div className="mb-1 flex flex-wrap items-center gap-2">
                        <h2 className="break-words text-base font-semibold tracking-tight">
                            {name}
                        </h2>
                        <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                            {type}
                        </span>
                    </div>
                </div>

                <ResourceStatusBadge
                    status={status}
                    title={getResourceStatusDescription(service, fields)}
                />
            </div>

            {vmMetrics && <VmMetricsDetails metrics={vmMetrics} />}

            {/* Attributes */}
            {attributes.length > 0 && (
                <div className="border-t border-border px-4 py-3">
                    <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        <Activity className="h-3.5 w-3.5" />
                        Resource details
                        <span className="ml-auto font-normal normal-case tracking-normal">
                            {attributes.length} attributes
                        </span>
                    </div>

                    <div className="grid grid-cols-1 gap-x-5">
                        {attributes
                            .slice(0, expanded ? undefined : 6)
                            .map(([key, value]) => (
                                <div
                                    key={key}
                                    className="flex min-w-0 items-start justify-between gap-3 border-b border-border/50 py-1.5 last:border-0"
                                >
                                    <span className="shrink-0 text-xs text-muted-foreground">
                                        {key}
                                    </span>

                                    <span
                                        className={`min-w-0 break-all text-right text-xs font-medium text-foreground ${key.toLowerCase().includes("id")
                                                ? "font-mono"
                                                : ""
                                            }`}
                                        title={value}
                                    >
                                        {value || "—"}
                                    </span>
                                </div>
                            ))}
                    </div>

                    {attributes.length > 6 && (
                        <button
                            type="button"
                            onClick={() => setExpanded(!expanded)}
                            className="mt-2 flex w-full items-center justify-center gap-1 rounded-md py-1.5 text-xs font-medium text-primary transition-colors hover:bg-muted"
                        >
                            {expanded
                                ? "Show less"
                                : `Show all ${attributes.length} attributes`}
                            {expanded ? (
                                <ChevronUp className="h-3.5 w-3.5" />
                            ) : (
                                <ChevronDown className="h-3.5 w-3.5" />
                            )}
                        </button>
                    )}
                </div>
            )}
        </section>
    );
}
