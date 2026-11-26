import {
  ServiceNodeType,
  TopologyApplication,
  TopologyNode,
  TopologyService,
} from "@/app/(keep)/topology-v2/model";
import { Edge } from "@xyflow/react";
import {
  edgeLabelBgBorderRadiusNoHover,
  edgeLabelBgPaddingNoHover,
  edgeLabelBgStyleNoHover,
  edgeMarkerEndNoHover,
} from "@/app/(keep)/topology-v2/ui/map/styles";
import { IncidentDto } from "@/entities/incidents/model";
import { KeyedMutator } from "swr";
import { AlertDto } from "@/entities/alerts/model";
import {
  getResourceName,
  getResourceStatus,
  inferConnectionState,
  RESOURCE_STATES,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import type { ResourceConnectionData } from "@/app/(keep)/topology-v2/ui/map/resource-status-edge";
import { getPortTraffic } from "@/app/(keep)/topology-v2/lib/port-traffic";

export function getNodesAndEdgesFromTopologyData(
  topologyData: TopologyService[],
  applicationsMap: Map<string, TopologyApplication>,
  allIncidents: IncidentDto[],
  allAlerts: AlertDto[],
  topologyMutator: KeyedMutator<TopologyService[]>
) {
  const nodeMap = new Map<string, TopologyNode>();
  const edgeMap = new Map<string, Edge>();
  const servicesById = new Map(
    topologyData.map((service) => [String(service.id), service])
  );
  const resourceStates = new Map(
    topologyData.map((service) => [
      String(service.id),
      {
        name: getResourceName(service),
        status: getResourceStatus(service),
      },
    ])
  );

  // Create nodes from service definitions
  for (const service of topologyData) {
    const numIncidentsToService = allIncidents.filter(
      (incident) =>
        incident.services.includes(service.display_name) ||
        incident.services.includes(service.service)
    );
    const node: ServiceNodeType = {
      id: service.id.toString(),
      type: "service",
      data: {
        ...service,
        incidents: numIncidentsToService.length,
        alerts: allAlerts.filter((alert) => alert.service === service.service)
          .length,
        topologyMutator,
      },
      position: { x: 0, y: 0 }, // Dagre will handle the actual positioning
      selectable: true,
    };
    if (service.application_ids.length > 0) {
      node.data.applications = service.application_ids
        .map((id) => {
          const app = applicationsMap.get(id);
          if (!app) {
            return null;
          }
          return {
            id: app.id,
            name: app.name,
          };
        })
        .filter((a) => !!a);
    }
    nodeMap.set(service.id.toString(), node);
    service.dependencies.forEach((dependency) => {
      const dependencyService = servicesById.get(String(dependency.serviceId));
      if (!dependencyService) return;
      const edgeId = dependency.id.toString();
      if (!edgeMap.has(edgeId)) {
        const source = resourceStates.get(String(service.id))!;
        const target = resourceStates.get(String(dependencyService.id))!;
        const state = inferConnectionState(source.status, target.status);
        const color = RESOURCE_STATES[state].color;
        const connectionData: ResourceConnectionData = {
          state,
          sourceName: source.name,
          targetName: target.name,
          sourceStatus: source.status.label,
          targetStatus: target.status.label,
          traffic: getPortTraffic(service) ?? getPortTraffic(dependencyService),
        };
        edgeMap.set(edgeId, {
          id: edgeId.toString(),
          type: "resourceStatus",
          source: service.id.toString(),
          target: dependencyService.id.toString(),
          label: dependency.protocol === "unknown" ? "" : dependency.protocol,
          data: connectionData,
          ariaLabel: `Connection ${source.name} to ${target.name}. Inferred condition: ${RESOURCE_STATES[state].label}.`,
          style: {
            stroke: color,
            strokeDasharray:
              state === "stopped"
                ? "8 4"
                : state === "unknown"
                  ? "3 4"
                  : undefined,
          },
          labelStyle: { fill: "#334155", fontSize: 11 },
          animated: false,
          labelBgPadding: edgeLabelBgPaddingNoHover,
          labelBgStyle: { ...edgeLabelBgStyleNoHover, stroke: color },
          labelBgBorderRadius: edgeLabelBgBorderRadiusNoHover,
          markerEnd: { ...edgeMarkerEndNoHover, color },
        });
      }
    });
  }

  return { nodeMap, edgeMap };
}
