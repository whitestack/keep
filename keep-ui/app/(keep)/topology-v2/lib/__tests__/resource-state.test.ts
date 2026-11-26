import {
  getResourceName,
  getResourceStatus,
  getResourceStatusDescription,
  inferConnectionState,
  parseDescription,
  type ResourceState,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";

function resource(overrides: Partial<TopologyService> = {}): TopologyService {
  return {
    id: "42",
    service: "93465999-0ee5-4358-948a-7155d285bdfe",
    display_name: "",
    category: "port",
    dependencies: [],
    application_ids: [],
    applications: [],
    is_manual: false,
    ...overrides,
  };
}

describe("resource descriptions and names", () => {
  it("preserves colons in IPs and MACs and ignores malformed fields", () => {
    expect(
      parseDescription(
        "garbage | : invalid | Name: | IP Address: 2001:db8::1 | MAC Address: aa:bb:cc:dd:ee:ff"
      )
    ).toEqual({
      Name: "",
      "IP Address": "2001:db8::1",
      "MAC Address": "aa:bb:cc:dd:ee:ff",
    });
    expect(parseDescription(null)).toEqual({});
  });

  it("prefers a real display name over the description name and IP", () => {
    expect(
      getResourceName(
        resource({
          display_name: "  eth0  ",
          description: "Name: other | IP Address: 10.0.0.1",
        })
      )
    ).toBe("eth0");
  });

  it("uses a description name if the display name is whitespace", () => {
    expect(
      getResourceName(
        resource({
          display_name: "  ",
          description: "name: interface-01 | IP Address: 10.0.0.1",
        })
      )
    ).toBe("interface-01");
  });

  it("labels unnamed ports using their IP", () => {
    expect(
      getResourceName(resource({ description: "Name: | IP Address: 10.0.0.1" }))
    ).toBe("Port 10.0.0.1");
    expect(getResourceName(resource({ ip_address: "2001:db8::1" }))).toBe(
      "Port 2001:db8::1"
    );
  });

  it("can use the description IP when the structured IP is a placeholder", () => {
    expect(
      getResourceName(
        resource({ ip_address: "N/A", description: "IP Address: 10.0.0.1" })
      )
    ).toBe("Port 10.0.0.1");
  });

  it.each([
    undefined,
    "IP Address: N/A",
    "IP Address: None",
    "Name: | IP Address: ",
  ])(
    "falls back to the source ID instead of the database ID when IP is missing: %s",
    (description) => {
      expect(getResourceName(resource({ description }))).toBe("Port 93465999");
    }
  );

  it("prefers the complete original port ID from the description", () => {
    expect(
      getResourceName(
        resource({
          description: "Port ID: abcdef01-2345-6789 | IP Address: N/A",
        })
      )
    ).toBe("Port abcdef01");
  });
});

describe("resource states", () => {
  it.each([
    ["hypervisor", "State: down | Status: enabled", "critical", "Down"],
    ["hypervisor", "State: down | Status: disabled", "critical", "Down"],
    ["hypervisor", "State: up | Status: enabled", "healthy", "Up"],
    ["hypervisor", "State: up | Status: disabled", "warning", "Disabled"],
    ["hypervisor", "Status: enabled", "unknown", "Unknown"],
    ["hypervisor", "State: unreported | Status: enabled", "unknown", "Unknown"],
    ["instance", "Status: ACTIVE", "healthy", "Active"],
    ["instance", "Status: ERROR", "critical", "Error"],
    ["instance", "Status: BUILD", "warning", "Building"],
    ["instance", "Status: REBOOT", "warning", "Rebooting"],
    ["instance", "Status: SHUTOFF", "stopped", "Shut off"],
    ["instance", "Status: PAUSED", "stopped", "Paused"],
    ["instance", "Status: SUSPENDED", "stopped", "Suspended"],
    ["port", "Status: ACTIVE", "healthy", "Active"],
    ["port", "Status: DOWN", "critical", "Down"],
    ["port", "Status: ERROR", "critical", "Error"],
    ["port", "Status: BUILD", "warning", "Building"],
    ["port", "Status: BACKUP", "unknown", "Unknown"],
    ["port", "Status: NOT_ACTIVE", "unknown", "Unknown"],
    ["port", "Status: ", "unknown", "Unknown"],
    ["port", "ordinary description", "unknown", "Unknown"],
  ])("interprets %s with %s as %s", (category, description, state, label) => {
    expect(getResourceStatus(resource({ category, description }))).toEqual({
      state,
      label,
    });
  });

  it("accepts mixed case fields and surrounding whitespace", () => {
    expect(
      getResourceStatus(
        resource({
          category: " HYPERVISOR ",
          description: " state : Up | status: ENABLED ",
        })
      )
    ).toEqual({ state: "healthy", label: "Up" });
  });

  it("keeps both original status fields available for explanations", () => {
    expect(
      getResourceStatusDescription(
        resource({ description: "State: down | Status: enabled" })
      )
    ).toBe("Status: enabled · State: down");
    expect(getResourceStatusDescription(resource())).toBe(
      "No resource state reported"
    );
  });
});

describe("inferred connection states", () => {
  it.each<[ResourceState, ResourceState, ResourceState]>([
    ["healthy", "healthy", "healthy"],
    ["healthy", "critical", "critical"],
    ["critical", "unknown", "critical"],
    ["warning", "critical", "critical"],
    ["healthy", "warning", "warning"],
    ["healthy", "stopped", "stopped"],
    ["healthy", "unknown", "unknown"],
    ["unknown", "unknown", "unknown"],
  ])("combines %s and %s as %s, symmetrically", (source, target, result) => {
    const a = { state: source, label: source };
    const b = { state: target, label: target };
    expect(inferConnectionState(a, b)).toBe(result);
    expect(inferConnectionState(b, a)).toBe(result);
  });
});
