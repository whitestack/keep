import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import {
  formatVmPercent,
  formatVmRam,
  getVmMetrics,
} from "@/app/(keep)/topology-v2/lib/vm-metrics";

const vm = (description: string): TopologyService => ({
  id: "1",
  service: "vm-id",
  category: "instance",
  display_name: "test-vm",
  description,
  application_ids: [],
  applications: [],
  dependencies: [],
  is_manual: false,
});

describe("VM metrics", () => {
  it("keeps valid zero usage and formats capacity separately from utilization", () => {
    const data = getVmMetrics(
      vm(
        "Status: ACTIVE | VM CPU percent: 0 | VM RAM percent: 20.55 | VM vCPUs: 4 | VM RAM capacity bytes: 8589934592 | VM metrics window: 5m | VM metrics updated at: 2026-11-12T07:00:00+00:00"
      )
    )!;
    expect(formatVmPercent(data.cpuPercent)).toBe("0%");
    expect(formatVmPercent(data.ramPercent)).toBe("20.6%");
    expect(data.vcpus).toBe(4);
    expect(formatVmRam(data.ramCapacityBytes)).toBe("8 GiB");
    expect(data.window).toBe("5m");
    expect(data.updatedAt).toBe("2026-11-12T07:00:00+00:00");
  });
  it("shows missing data for older topology descriptions", () => {
    const data = getVmMetrics(vm("Status: ACTIVE"))!;
    expect(formatVmPercent(data.cpuPercent)).toBe("No data");
    expect(formatVmRam(data.ramCapacityBytes)).toBe("No data");
    expect(data.vcpus).toBeNull();
  });
  it.each(["SHUTOFF", "PAUSED", "ERROR", "BUILD", ""])(
    "ignores reported usage when status is %s",
    (status) => {
      const data = getVmMetrics(
        vm(
          `Status: ${status} | VM CPU percent: 0 | VM RAM percent: 0 | VM vCPUs: 1`
        )
      )!;
      expect(data.cpuPercent).toBeNull();
      expect(data.ramPercent).toBeNull();
      expect(data.vcpus).toBe(1);
    }
  );
  it.each(["NaN", "Infinity", "-1", "101", "", "garbage"])(
    "rejects invalid percentages: %s",
    (value) => {
      const data = getVmMetrics(
        vm(
          `Status: ACTIVE | VM CPU percent: ${value} | VM RAM percent: ${value}`
        )
      )!;
      expect(data.cpuPercent).toBeNull();
      expect(data.ramPercent).toBeNull();
    }
  );
  it("rejects invalid capacity, dates and windows", () => {
    const data = getVmMetrics(
      vm(
        "Status: ACTIVE | VM vCPUs: 1.5 | VM RAM capacity bytes: 0 | VM metrics updated at: invalid | VM metrics window: forever"
      )
    )!;
    expect(data.vcpus).toBeNull();
    expect(data.ramCapacityBytes).toBeNull();
    expect(data.updatedAt).toBeNull();
    expect(data.window).toBeNull();
  });
  it("does not add VM metrics to ports or hypervisors", () => {
    expect(getVmMetrics({ ...vm(""), category: "port" })).toBeUndefined();
    expect(getVmMetrics({ ...vm(""), category: "hypervisor" })).toBeUndefined();
  });
  it("preserves small nonzero CPU usage", () => {
    expect(formatVmPercent(0.01)).toBe("<0.1%");
  });
});
