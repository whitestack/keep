import { getNodesAndEdgesFromTopologyData } from "@/app/(keep)/topology-v2/ui/map/getNodesAndEdgesFromTopologyData";
import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import { RESOURCE_STATES } from "@/app/(keep)/topology-v2/lib/resource-state";

function service(overrides: Partial<TopologyService>): TopologyService {
  return {
    id: "port",
    service: "original-port-uuid",
    display_name: "",
    description: "Status: ACTIVE | IP Address: 10.0.0.1",
    category: "port",
    application_ids: [],
    applications: [],
    dependencies: [],
    is_manual: false,
    ...overrides,
  };
}

function build(source: TopologyService, target?: TopologyService) {
  return getNodesAndEdgesFromTopologyData(
    [source, ...(target ? [target] : [])],
    new Map(),
    [],
    [],
    jest.fn()
  );
}

const port = service({
  dependencies: [
    {
      id: "connection",
      serviceId: "host",
      serviceName: "ocp3",
      protocol: "connected_to",
    },
  ],
});
const host = service({
  id: "host",
  service: "ocp3",
  display_name: "ocp3",
  category: "hypervisor",
  description: "State: up | Status: enabled",
});

describe("topology connections", () => {
  it("preserves original IDs, names and relations while adding inferred presentation data", () => {
    const { nodeMap, edgeMap } = build(port, host);
    expect(nodeMap.get("port")?.data).toMatchObject({
      display_name: "",
      service: "original-port-uuid",
    });
    const edge = edgeMap.get("connection");
    expect(edge).toMatchObject({
      id: "connection",
      source: "port",
      target: "host",
      label: "connected_to",
      type: "resourceStatus",
      data: {
        state: "healthy",
        sourceName: "Port 10.0.0.1",
        targetName: "ocp3",
      },
    });
    expect(edge?.ariaLabel).toContain("Inferred condition");
  });

  it("shows an enabled but down hypervisor as an affected connection", () => {
    const edge = build(port, {
      ...host,
      description: "State: down | Status: enabled",
    }).edgeMap.get("connection");
    expect(edge?.data?.state).toBe("critical");
    expect(edge?.style?.stroke).toBe(RESOURCE_STATES.critical.color);
    expect(edge?.markerEnd).toMatchObject({ color: edge?.style?.stroke });
    expect(edge?.labelBgStyle?.stroke).toBe(edge?.style?.stroke);
  });

  it("does not imply a healthy connection when an endpoint state is missing", () => {
    const edge = build({ ...port, description: undefined }, host).edgeMap.get(
      "connection"
    );
    expect(edge?.data?.state).toBe("unknown");
    expect(edge?.style?.strokeDasharray).toBeTruthy();
  });

  it("keeps empty protocol labels and omits edges to absent resources", () => {
    const noProtocol = {
      ...port,
      dependencies: [{ ...port.dependencies[0], protocol: "unknown" }],
    };
    expect(build(noProtocol, host).edgeMap.get("connection")?.label).toBe("");
    expect(build(port).edgeMap.size).toBe(0);
  });

  it("attaches the same port traffic to both virtual relationships", () => {
    const measuredPort = {
      ...port,
      description:
        port.description +
        " | Traffic RX bps: 0 | Traffic TX bps: 2500 | Traffic window: 5m",
    };
    const vm = service({
      id: "vm",
      service: "vm-uuid",
      category: "instance",
      display_name: "nfs-server",
      dependencies: [
        {
          id: "vm-port",
          serviceId: "port",
          serviceName: "",
          protocol: "connected_to",
        },
      ],
    });
    const { edgeMap } = getNodesAndEdgesFromTopologyData(
      [vm, measuredPort, host],
      new Map(),
      [],
      [],
      jest.fn()
    );
    for (const id of ["vm-port", "connection"]) {
      expect(edgeMap.get(id)?.data?.traffic).toMatchObject({
        portName: "Port 10.0.0.1",
        receivedBps: 0,
        transmittedBps: 2500,
        window: "5m",
      });
      expect(edgeMap.get(id)?.data?.state).toBe("healthy");
    }
  });
});
