
"use client";

import {
    Server,
    Network,
    Monitor,
    CircleCheck,
    CircleAlert,
    CircleX,
    ChevronDown,
    ChevronUp,
    Activity,
    Boxes,
} from "lucide-react";
import { useMemo, useState } from "react";
import { TopologyService } from "../../model/models";

type Props = {
    service: TopologyService;
};

function parseDescription(description?: string | null): Record<string, string> {
    if (!description) return {};

    return Object.fromEntries(
        description
            .trim()
            .split("|")
            .map((part) => {
                const separator = part.indexOf(":");
                if (separator === -1) return null;

                return [
                    part.slice(0, separator).trim(),
                    part.slice(separator + 1).trim(),
                ];
            })
            .filter((entry): entry is [string, string] => entry !== null)
    );
}

function getResourceType(service: TopologyService, fields: Record<string, string>) {
    const text = `${service.display_name ?? ""} ${service.service ?? ""} ${Object.keys(fields).join(" ")}`.toLowerCase();

    if (text.includes("hypervisor")) return "Hypervisor";
    if (text.includes("port")) return "Network Port";
    if (text.includes("instance")) return "Instance";
    return "Resource";
}

function getStatus(fields: Record<string, string>) {
    const raw = (fields.Status ?? fields.State ?? "").toLowerCase();

    if (["error", "down", "disabled", "failed", "inactive"].some((s) => raw.includes(s))) {
        return { label: fields.Status ?? fields.State, tone: "red" as const };
    }

    if (["active", "up", "enabled", "healthy", "available"].some((s) => raw.includes(s))) {
        return { label: fields.Status ?? fields.State, tone: "green" as const };
    }

    return { label: fields.Status ?? fields.State ?? "Unknown", tone: "neutral" as const };
}

const statusStyles = {
    green: "bg-emerald-500/10 text-emerald-600 ring-emerald-500/20",
    red: "bg-red-500/10 text-red-600 ring-red-500/20",
    neutral: "bg-muted text-muted-foreground ring-border",
};

function getIcon(type: string) {
    if (type === "Hypervisor") return Server;
    if (type === "Network Port") return Network;
    if (type === "Instance") return Monitor;
    return Boxes;
}

export default function ServiceDetailsCard({ service }: Props) {
    const [expanded, setExpanded] = useState(false);

    const fields = useMemo(
        () => parseDescription(service.description),
        [service.description]
    );

    const type = getResourceType(service, fields);
    const Icon = getIcon(type);
    const status = getStatus(fields);

    const attributes = Object.entries(fields).filter(
        ([key]) => !["Status", "State"].includes(key)
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
                            {service.display_name || service.service || "Unnamed resource"}
                        </h2>
                        <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                            {type}
                        </span>
                    </div>
                </div>

                <span
                    className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${statusStyles[status.tone]}`}
                >
                    {status.tone === "green" ? (
                        <CircleCheck className="h-3.5 w-3.5" />
                    ) : status.tone === "red" ? (
                        <CircleX className="h-3.5 w-3.5" />
                    ) : (
                        <CircleAlert className="h-3.5 w-3.5" />
                    )}
                    {status.label}
                </span>
            </div>

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
