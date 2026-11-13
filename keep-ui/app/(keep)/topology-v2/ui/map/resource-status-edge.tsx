import {
  BaseEdge,
  getBezierPath,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";
import {
  RESOURCE_STATES,
  type ResourceState,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import {
  formatBitrate,
  type PortTraffic,
} from "@/app/(keep)/topology-v2/lib/port-traffic";
import { Tooltip } from "@/shared/ui/Tooltip";
import { ConnectionTooltip } from "@/app/(keep)/topology-v2/ui/map/connection-tooltip";

export type ResourceConnectionData = {
  state: ResourceState;
  sourceName: string;
  targetName: string;
  sourceStatus: string;
  targetStatus: string;
  traffic?: PortTraffic;
};

export function ResourceStatusEdge(
  props: EdgeProps<Edge<ResourceConnectionData>>
) {
  const [path, labelX, labelY] = getBezierPath(props);
  const data = props.data;
  const condition = data
    ? `Inferred condition: ${RESOURCE_STATES[data.state].label}. ${data.sourceName}: ${data.sourceStatus}; ${data.targetName}: ${data.targetStatus}. Not measured link health.`
    : "Connection condition unknown";
  const description = data?.traffic
    ? `${condition} Virtual interface ${data.traffic.portName}. Received: ${formatBitrate(data.traffic.receivedBps)}. Transmitted: ${formatBitrate(data.traffic.transmittedBps)}.`
    : condition;

  return (
    <Tooltip
      asChild
      content={<ConnectionTooltip data={data} />}
      className="z-50 max-w-80"
    >
      <g tabIndex={0} role="img" aria-label={description}>
        <BaseEdge
          id={props.id}
          path={path}
          labelX={labelX}
          labelY={labelY}
          label={props.label}
          labelStyle={props.labelStyle}
          labelShowBg={props.labelShowBg}
          labelBgStyle={props.labelBgStyle}
          labelBgPadding={props.labelBgPadding}
          labelBgBorderRadius={props.labelBgBorderRadius}
          style={props.style}
          markerStart={props.markerStart}
          markerEnd={props.markerEnd}
          interactionWidth={props.interactionWidth ?? 24}
          className="topology-status-edge"
        />
      </g>
    </Tooltip>
  );
}
