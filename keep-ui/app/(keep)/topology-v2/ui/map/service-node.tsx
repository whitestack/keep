import React, { useState } from "react";
import { Handle, NodeProps, Position } from "@xyflow/react";
import {
  autoPlacement,
  autoUpdate,
  FloatingPortal,
  offset,
  shift,
  useFloating,
} from "@floating-ui/react";
import { useRouter } from "next/navigation";
import { ServiceNodeType } from "@/app/(keep)/topology-v2/model/models";
import { Badge } from "@tremor/react";
import { getColorForUUID } from "@/app/(keep)/topology-v2/lib/badge-colors";
import { clsx } from "clsx";
import { DynamicImageProviderIcon } from "@/components/ui";
import ServiceDetailsCard from "@/app/(keep)/topology-v2/ui/map/service-detail-card";
import {
  getResourceName,
  getResourceStatus,
  getResourceStatusDescription,
} from "@/app/(keep)/topology-v2/lib/resource-state";
import { ResourceStatusBadge } from "@/app/(keep)/topology-v2/ui/map/resource-status-badge";
import { getVmMetrics } from "@/app/(keep)/topology-v2/lib/vm-metrics";
import { VmMetricsSummary } from "@/app/(keep)/topology-v2/ui/map/vm-metrics";

const THRESHOLD = 5;

export function ServiceNode({ data, selected }: NodeProps<ServiceNodeType>) {
  const router = useRouter();
  const [showDetails, setShowDetails] = useState(false);
  const { refs, floatingStyles, placement, isPositioned } = useFloating({
    open: showDetails,
    strategy: "fixed",
    middleware: [
      offset(10),
      autoPlacement({ padding: 12 }),
      shift({ padding: 12 }),
    ],
    whileElementsMounted: (reference, floating, update) =>
      autoUpdate(reference, floating, update, { animationFrame: true }),
  });
  const name = getResourceName(data);
  const status = getResourceStatus(data);
  const category = data.category?.trim().toLowerCase();
  const vmMetrics = getVmMetrics(data);
  const serviceIdentifier = data.display_name?.trim() || data.service;

  const handleIncidentClick = () => {
    router.push(`/incidents?services=${encodeURIComponent(serviceIdentifier)}`);
  };

  const handleAlertClick = () => {
    const cel = `service==${JSON.stringify(serviceIdentifier)}`;
    router.push(`/alerts/feed?cel=${encodeURIComponent(cel)}`);
  };

  const incidentsCount = data.incidents ?? 0;
  const alertsCount = data.alerts ?? 0;
  const badgeColor =
    incidentsCount < THRESHOLD ? "bg-orange-500" : "bg-red-500";

  return (
    <>
      <div
        ref={refs.setReference}
        className={clsx(
          "flex h-full w-full flex-col gap-2 bg-white p-3 border-2 border-gray-200 rounded-xl shadow-lg relative transition-colors dark:bg-slate-900 dark:text-slate-100",
          selected && "border-tremor-brand"
        )}
        onMouseEnter={() => setShowDetails(true)}
        onMouseLeave={() => setShowDetails(false)}
      >
        <div className="flex items-center gap-3">
          <strong
            className="min-w-0 flex-1 break-words text-base font-semibold leading-tight line-clamp-2"
            title={name}
          >
            {name}
          </strong>

          {category && (
            <div
              className={`
                flex h-11 w-11 shrink-0
                items-center justify-center
                rounded-lg bg-slate-100
                ring-1 ring-inset ring-gray-200
                dark:bg-blue-500/10 dark:ring-gray-700
              `}
              title={category}
            >
              <DynamicImageProviderIcon
                className="block object-contain"
                alt={category}
                height={28}
                width={28}
                title={category}
                src={`/icons/${category}-icon.svg`}
              />
            </div>
          )}
        </div>
        <ResourceStatusBadge
          status={status}
          title={getResourceStatusDescription(data)}
        />
        {vmMetrics && <VmMetricsSummary metrics={vmMetrics} />}
        {incidentsCount > 0 ? (
          <span
            className={`absolute top-[-17px] right-[-20px] mt-2 mr-2 px-2 py-1 text-white text-[7px] leading-[7px] font-bold rounded-full ${badgeColor} hover:cursor-pointer`}
            onClick={handleIncidentClick}
          >
            {incidentsCount} {incidentsCount === 1 ? "incident" : "incidents"}
          </span>
        ) : alertsCount > 0 ? (
          <span
            className={`absolute top-[-17px] right-[-20px] mt-2 mr-2 px-2 py-1 text-white text-[7px] leading-[7px] font-bold rounded-full ${badgeColor} hover:cursor-pointer`}
            onClick={handleAlertClick}
          >
            {alertsCount} {alertsCount === 1 ? "alert" : "alerts"}
          </span>
        ) : (
          <></>
        )}
        <div className="flex flex-wrap gap-1">
          {data?.applications?.map((app) => {
            const color = getColorForUUID(app.id);
            return (
              <Badge key={app.id} color={color}>
                {app.name}
              </Badge>
            );
          })}
        </div>
      </div>

      {showDetails && (
        <FloatingPortal>
          <div
            ref={refs.setFloating}
            className="z-50"
            style={{
              ...floatingStyles,
              visibility: isPositioned ? "visible" : "hidden",
            }}
            data-placement={placement}
          >
            <ServiceDetailsCard service={data} />
          </div>
        </FloatingPortal>
      )}

      <>
        <Handle
          type="source"
          className={clsx(data.is_manual === true && "!opacity-100")}
          position={Position.Right}
          id="right"
        />
        <Handle
          type="target"
          className={clsx(data.is_manual === true && "!opacity-100")}
          position={Position.Left}
          id="left"
        />
      </>
    </>
  );
}
