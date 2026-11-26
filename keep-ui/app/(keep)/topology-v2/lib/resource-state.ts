import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";

export type ResourceState =
  | "healthy"
  | "warning"
  | "critical"
  | "stopped"
  | "unknown";
export type ResourceStatus = { state: ResourceState; label: string };

type Resource = Pick<
  TopologyService,
  "id" | "service" | "category" | "display_name" | "description" | "ip_address"
>;

export const RESOURCE_STATES: Record<
  ResourceState,
  { label: string; color: string }
> = {
  healthy: { label: "Operational", color: "#15803d" },
  warning: { label: "Warning / transition", color: "#eab308" },
  critical: { label: "Down / error", color: "#dc2626" },
  stopped: { label: "Stopped / paused", color: "#2563eb" },
  unknown: { label: "Unknown / no data", color: "#64748b" },
};

export function parseDescription(
  description?: string | null
): Record<string, string> {
  return Object.fromEntries(
    (description ?? "").split("|").flatMap((part) => {
      const separator = part.indexOf(":");
      if (separator < 0) return [];
      const key = part.slice(0, separator).trim();
      return key ? [[key, part.slice(separator + 1).trim()]] : [];
    })
  );
}

function field(fields: Record<string, string>, name: string): string {
  return (
    Object.entries(fields).find(
      ([key]) => key.toLowerCase() === name.toLowerCase()
    )?.[1] ?? ""
  );
}

export function getResourceName(
  resource: Resource,
  fields = parseDescription(resource.description)
): string {
  const name = resource.display_name?.trim() || field(fields, "Name").trim();
  if (name) return name;

  const type = resource.category?.trim().toLowerCase();
  if (type === "port") {
    const ip = [resource.ip_address, field(fields, "IP Address")]
      .map((value) => value?.trim())
      .find(
        (value) =>
          value &&
          !["n/a", "none", "null", "unknown", "-"].includes(value.toLowerCase())
      );
    if (ip) {
      return `Port ${ip}`;
    }
  }

  const id =
    field(
      fields,
      `${type === "instance" ? "Instance" : type === "hypervisor" ? "Hypervisor" : "Port"} ID`
    ) ||
    resource.service?.trim() ||
    resource.id;
  const typeName =
    type === "port"
      ? "Port"
      : type === "instance"
        ? "Instance"
        : type === "hypervisor"
          ? "Hypervisor"
          : "Resource";
  return id ? `${typeName} ${String(id).slice(0, 8)}` : "<Unnamed>";
}

const instanceStatuses: Record<string, ResourceStatus> = {
  ACTIVE: { state: "healthy", label: "Active" },
  ERROR: { state: "critical", label: "Error" },
  BUILD: { state: "warning", label: "Building" },
  REBUILD: { state: "warning", label: "Rebuilding" },
  REBOOT: { state: "warning", label: "Rebooting" },
  HARD_REBOOT: { state: "warning", label: "Rebooting" },
  RESIZE: { state: "warning", label: "Resizing" },
  VERIFY_RESIZE: { state: "warning", label: "Verify resize" },
  REVERT_RESIZE: { state: "warning", label: "Reverting resize" },
  MIGRATING: { state: "warning", label: "Migrating" },
  RESCUE: { state: "warning", label: "Rescue" },
  SHUTOFF: { state: "stopped", label: "Shut off" },
  PAUSED: { state: "stopped", label: "Paused" },
  SUSPENDED: { state: "stopped", label: "Suspended" },
  SHELVED: { state: "stopped", label: "Shelved" },
  SHELVED_OFFLOADED: { state: "stopped", label: "Shelved" },
};

const portStatuses: Record<string, ResourceStatus> = {
  ACTIVE: { state: "healthy", label: "Active" },
  DOWN: { state: "critical", label: "Down" },
  ERROR: { state: "critical", label: "Error" },
  BUILD: { state: "warning", label: "Building" },
};

const genericStatuses: Record<string, ResourceStatus> = {
  ...portStatuses,
  UP: { state: "healthy", label: "Up" },
  HEALTHY: { state: "healthy", label: "Healthy" },
  AVAILABLE: { state: "healthy", label: "Available" },
  FAILED: { state: "critical", label: "Failed" },
  DISABLED: { state: "warning", label: "Disabled" },
  INACTIVE: { state: "stopped", label: "Inactive" },
  STOPPED: { state: "stopped", label: "Stopped" },
};

export function getResourceStatus(
  resource: Resource,
  fields = parseDescription(resource.description)
): ResourceStatus {
  const status = field(fields, "Status").trim().toUpperCase();
  const state = field(fields, "State").trim().toUpperCase();
  const type = resource.category?.trim().toLowerCase();

  if (type === "hypervisor") {
    // Availability and administrative status are independent in Nova.
    if (state === "DOWN") return { state: "critical", label: "Down" };
    if (status === "DISABLED") return { state: "warning", label: "Disabled" };
    if (state === "UP" && status === "ENABLED")
      return { state: "healthy", label: "Up" };
    return { state: "unknown", label: "Unknown" };
  }

  const statuses =
    type === "instance"
      ? instanceStatuses
      : type === "port"
        ? portStatuses
        : genericStatuses;
  return statuses[status || state] ?? { state: "unknown", label: "Unknown" };
}

export function getResourceStatusDescription(
  resource: Resource,
  fields = parseDescription(resource.description)
): string {
  const status = field(fields, "Status");
  const state = field(fields, "State");
  return (
    [status && `Status: ${status}`, state && `State: ${state}`]
      .filter(Boolean)
      .join(" · ") || "No resource state reported"
  );
}

export function inferConnectionState(
  source: ResourceStatus,
  target: ResourceStatus
): ResourceState {
  // These are endpoint conditions, never a measurement of the physical link.
  return (
    (["critical", "warning", "stopped", "unknown", "healthy"] as const).find(
      (state) => source.state === state || target.state === state
    ) ?? "unknown"
  );
}
