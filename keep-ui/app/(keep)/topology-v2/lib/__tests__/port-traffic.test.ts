import {
  formatBitrate,
  getPortTraffic,
  isTrafficField,
} from "@/app/(keep)/topology-v2/lib/port-traffic";
import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";

const port: TopologyService = {
  id: "port",
  service: "full-source-port-id",
  category: "port",
  display_name: "",
  dependencies: [],
  application_ids: [],
  applications: [],
  is_manual: false,
};

describe("virtual interface traffic", () => {
  it("retains a valid zero independently from a missing direction", () => {
    expect(
      getPortTraffic({
        ...port,
        description:
          "IP Address: 10.100.32.142 | Traffic RX bps: 0 | Traffic window: 5m | Traffic updated at: 2026-11-12T10:00:00+00:00",
      })
    ).toEqual({
      portName: "Port 10.100.32.142",
      receivedBps: 0,
      transmittedBps: null,
      window: "5m",
      updatedAt: "2026-11-12T10:00:00+00:00",
    });
  });

  it.each(["", "NaN", "Infinity", "-1", "not a number"])(
    "does not turn an invalid rate into zero: %s",
    (value) => {
      expect(
        getPortTraffic({
          ...port,
          description: `Traffic RX bps: ${value} | Traffic TX bps: 1250`,
        })
      ).toMatchObject({ receivedBps: null, transmittedBps: 1250 });
    }
  );

  it("accepts legacy descriptions and hides invalid metadata", () => {
    expect(
      getPortTraffic({
        ...port,
        description:
          "Status: ACTIVE | Traffic window: invalid | Traffic updated at: nope",
      })
    ).toMatchObject({
      receivedBps: null,
      transmittedBps: null,
      updatedAt: null,
      window: null,
    });
    expect(getPortTraffic({ ...port, category: "instance" })).toBeUndefined();
  });

  it.each([
    [0, "0 bps"],
    [14.033333, "14.03 bps"],
    [2370.6, "2.37 kbps"],
    [1234567, "1.23 Mbps"],
    [4500000000, "4.5 Gbps"],
    [0.001, "<0.01 bps"],
    [null, "No traffic data"],
    [NaN, "No traffic data"],
    [-1, "No traffic data"],
  ])("formats %s as %s", (rate, expected) => {
    expect(formatBitrate(rate)).toBe(expected);
  });

  it("identifies only traffic attributes for the node-detail filter", () => {
    expect(isTrafficField(" Traffic RX bps ")).toBe(true);
    expect(isTrafficField("Status")).toBe(false);
    expect(isTrafficField("IP Address")).toBe(false);
  });
});
