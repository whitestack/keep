import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import {
  getResourceStatus,
  parseDescription,
} from "@/app/(keep)/topology-v2/lib/resource-state";

export type VmMetrics = {
  cpuPercent: number | null;
  ramPercent: number | null;
  vcpus: number | null;
  ramCapacityBytes: number | null;
  window: string | null;
  updatedAt: string | null;
};

export function isVmMetricsField(key: string): boolean {
  return /^vm (cpu percent|ram percent|vcpus|ram capacity bytes|metrics window|metrics updated at)$/i.test(
    key.trim()
  );
}

function number(value: string | undefined): number | null {
  if (!value?.trim()) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

export function getVmMetrics(service: TopologyService): VmMetrics | undefined {
  if (service.category?.trim().toLowerCase() !== "instance") return undefined;
  const fields = Object.fromEntries(
    Object.entries(parseDescription(service.description)).map(
      ([key, value]) => [key.toLowerCase(), value]
    )
  );
  const active = getResourceStatus(service).label === "Active";
  const percent = (key: string) => {
    const value = number(fields[key]);
    return active && value !== null && value <= 100 ? value : null;
  };
  const vcpus = number(fields["vm vcpus"]);
  const ram = number(fields["vm ram capacity bytes"]);
  const updatedAt = fields["vm metrics updated at"];
  return {
    cpuPercent: percent("vm cpu percent"),
    ramPercent: percent("vm ram percent"),
    vcpus:
      vcpus !== null && vcpus > 0 && Number.isInteger(vcpus) ? vcpus : null,
    ramCapacityBytes: ram !== null && ram > 0 ? ram : null,
    window: /^[1-9]\d*(ms|s|m|h|d|w|y)$/.test(fields["vm metrics window"] ?? "")
      ? fields["vm metrics window"]
      : null,
    updatedAt:
      updatedAt && Number.isFinite(Date.parse(updatedAt)) ? updatedAt : null,
  };
}

export function formatVmPercent(value: number | null): string {
  if (value === null) return "No data";
  if (value > 0 && value < 0.1) return "<0.1%";
  return `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(value)}%`;
}

export function formatVmRam(bytes: number | null): string {
  return bytes === null
    ? "No data"
    : `${new Intl.NumberFormat("en", { maximumFractionDigits: 2 }).format(bytes / 1024 ** 3)} GiB`;
}
