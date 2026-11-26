import React from "react";
import { render, screen, within } from "@testing-library/react";
import ServiceDetailsCard from "@/app/(keep)/topology-v2/ui/map/service-detail-card";
import { ResourceStatusBadge } from "@/app/(keep)/topology-v2/ui/map/resource-status-badge";
import type { TopologyService } from "@/app/(keep)/topology-v2/model/models";
import { VmMetricsSummary } from "@/app/(keep)/topology-v2/ui/map/vm-metrics";
import { getVmMetrics } from "@/app/(keep)/topology-v2/lib/vm-metrics";

const resource: TopologyService = {
  id: "1",
  service: "source-id",
  display_name: "",
  category: "port",
  application_ids: [],
  applications: [],
  dependencies: [],
  is_manual: false,
};

describe("resource presentation", () => {
  it("shows VM utilization in the box and assigned capacity in hover details", () => {
    const vm = {
      ...resource,
      category: "instance",
      display_name: "nfs-server",
      description:
        "Status: ACTIVE | VM CPU percent: 0 | VM RAM percent: 18.6 | VM vCPUs: 1 | VM RAM capacity bytes: 2147483648 | VM metrics window: 5m",
    };
    const summary = render(<VmMetricsSummary metrics={getVmMetrics(vm)!} />);
    expect(screen.getByText("CPU")).toBeInTheDocument();
    expect(screen.getByText("0%")).toBeInTheDocument();
    expect(screen.getByText("18.6%")).toBeInTheDocument();
    expect(screen.queryByText("Assigned vCPUs")).not.toBeInTheDocument();
    summary.unmount();
    render(<ServiceDetailsCard service={vm} />);
    expect(screen.getByText("Assigned vCPUs")).toBeInTheDocument();
    expect(screen.getByText("Maximum assigned RAM")).toBeInTheDocument();
    expect(screen.getByText("2 GiB")).toBeInTheDocument();
    expect(
      screen.getByLabelText("Resource status: Active")
    ).toBeInTheDocument();
    expect(screen.queryByText("VM RAM capacity bytes")).not.toBeInTheDocument();
  });
  it("shows missing utilization without hiding known stopped VM capacity", () => {
    const vm = {
      ...resource,
      category: "instance",
      description:
        "Status: SHUTOFF | VM CPU percent: 0 | VM RAM percent: 0 | VM vCPUs: 1 | VM RAM capacity bytes: 2147483648",
    };
    render(
      <>
        <VmMetricsSummary metrics={getVmMetrics(vm)!} />
        <ServiceDetailsCard service={vm} />
      </>
    );
    expect(
      within(screen.getByLabelText("VM utilization at last pull")).getAllByText(
        "No data"
      )
    ).toHaveLength(2);
    expect(screen.getByText("2 GiB")).toBeInTheDocument();
    expect(
      screen.getByLabelText("Resource status: Shut off")
    ).toBeInTheDocument();
  });
  it("reserves traffic metrics for connections rather than node details", () => {
    render(
      <ServiceDetailsCard
        service={{
          ...resource,
          description:
            "Status: ACTIVE | IP Address: 10.0.0.1 | Traffic RX bps: 0 | Traffic TX bps: 1234 | Traffic window: 5m",
        }}
      />
    );
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    expect(screen.queryByText("Traffic RX bps")).not.toBeInTheDocument();
    expect(screen.queryByText("Traffic TX bps")).not.toBeInTheDocument();
    expect(screen.queryByText("Traffic window")).not.toBeInTheDocument();
  });
  it("identifies an unnamed port by IP while retaining its full original attributes", () => {
    render(
      <ServiceDetailsCard
        service={{
          ...resource,
          description:
            "Name: | Port ID: full-original-id | IP Address: 2001:db8::1 | Status: ACTIVE",
        }}
      />
    );
    expect(
      screen.getByRole("heading", { name: "Port 2001:db8::1" })
    ).toBeInTheDocument();
    expect(screen.getByText("full-original-id")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    expect(
      screen.getByLabelText("Resource status: Active")
    ).toBeInTheDocument();
  });

  it("shows the down condition and both raw hypervisor fields", () => {
    render(
      <ServiceDetailsCard
        service={{
          ...resource,
          category: "hypervisor",
          display_name: "ocp3",
          description: "State: down | Status: enabled",
        }}
      />
    );
    expect(screen.getByLabelText("Resource status: Down")).toHaveAttribute(
      "title",
      "Status: enabled · State: down"
    );
    expect(screen.getByText("down")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
  });

  it("distinguishes stopped resources from unknown resources without relying on color", () => {
    render(
      <>
        <ResourceStatusBadge status={{ state: "stopped", label: "Shut off" }} />
        <ResourceStatusBadge status={{ state: "unknown", label: "Unknown" }} />
      </>
    );
    expect(
      screen.getByLabelText("Resource status: Shut off")
    ).toHaveTextContent("Shut off");
    expect(screen.getByLabelText("Resource status: Unknown")).toHaveTextContent(
      "Unknown"
    );
  });
});
