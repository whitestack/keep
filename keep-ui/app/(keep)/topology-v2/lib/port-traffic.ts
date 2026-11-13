import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import {
  getResourceName,
  parseDescription,
} from "@/app/(keep)/topology-v2/lib/resource-state";

export type PortTraffic = {
  portName: string;
  receivedBps: number | null;
  transmittedBps: number | null;
  window: string | null;
  updatedAt: string | null;
};

export function isTrafficField(key: string): boolean {
  return key.trim().toLowerCase().startsWith("traffic ");
}

function parseRate(value: string | undefined): number | null {
  if (!value?.trim()) return null;
  const rate = Number(value);
  return Number.isFinite(rate) && rate >= 0 ? rate : null;
}

export function getPortTraffic(
  service: TopologyService
): PortTraffic | undefined {
  if (service.category?.trim().toLowerCase() !== "port") return undefined;
  const fields = Object.fromEntries(
    Object.entries(parseDescription(service.description)).map(
      ([key, value]) => [key.toLowerCase(), value]
    )
  );
  const updatedAt = fields["traffic updated at"];
  return {
    portName: getResourceName(service),
    receivedBps: parseRate(fields["traffic rx bps"]),
    transmittedBps: parseRate(fields["traffic tx bps"]),
    window: /^[1-9]\d*(ms|s|m|h|d|w|y)$/.test(fields["traffic window"] ?? "")
      ? fields["traffic window"]
      : null,
    updatedAt:
      updatedAt && Number.isFinite(Date.parse(updatedAt)) ? updatedAt : null,
  };
}

export function formatBitrate(rate: number | null): string {
  if (rate === null || !Number.isFinite(rate) || rate < 0)
    return "No traffic data";
  if (rate > 0 && rate < 0.01) return "<0.01 bps";
  const units = ["bps", "kbps", "Mbps", "Gbps", "Tbps"];
  let scaled = rate;
  let index = 0;
  while (scaled >= 999.995 && index < units.length - 1) {
    scaled /= 1000;
    index++;
  }
  return `${new Intl.NumberFormat("en", {
    maximumFractionDigits: 2,
    notation: scaled >= 1e6 ? "scientific" : "standard",
  }).format(scaled)} ${units[index]}`;
}
