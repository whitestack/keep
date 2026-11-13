import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ConnectionTooltip } from "@/app/(keep)/topology-v2/ui/map/connection-tooltip";
import {
  ResourceStatusEdge,
  type ResourceConnectionData,
} from "@/app/(keep)/topology-v2/ui/map/resource-status-edge";

jest.mock("@xyflow/react", () => ({
  BaseEdge: () => <path d="M0 0 L100 0" />,
  getBezierPath: () => ["M0 0 L100 0", 50, 0],
}));

const data: ResourceConnectionData = {
  state: "healthy",
  sourceName: "nfs-server",
  targetName: "Port 10.100.32.142",
  sourceStatus: "Active",
  targetStatus: "Active",
  traffic: {
    portName: "Port 10.100.32.142",
    receivedBps: 0,
    transmittedBps: 2370.6,
    window: "5m",
    updatedAt: "2026-11-12T10:00:00+00:00",
  },
};

describe("connection traffic tooltip", () => {
  it("shows units, a real zero, the averaging window and the update time", () => {
    render(<ConnectionTooltip data={data} />);
    expect(screen.getByText("0 bps")).toBeInTheDocument();
    expect(screen.getByText("2.37 kbps")).toBeInTheDocument();
    expect(screen.getByText("Average over 5m")).toBeInTheDocument();
    expect(document.querySelector("time")).toHaveAttribute(
      "dateTime",
      data.traffic!.updatedAt
    );
    expect(
      screen.getByText(/Inferred condition: Operational/)
    ).toBeInTheDocument();
  });

  it("shows missing directions independently without changing resource health", () => {
    render(
      <ConnectionTooltip
        data={{
          ...data,
          traffic: { ...data.traffic!, receivedBps: null, transmittedBps: 0 },
        }}
      />
    );
    expect(screen.getByText("No traffic data")).toBeInTheDocument();
    expect(screen.getByText("0 bps")).toBeInTheDocument();
    expect(
      screen.getByText(/Inferred condition: Operational/)
    ).toBeInTheDocument();
  });

  it("does not invent interface metrics for a non-port connection", () => {
    render(<ConnectionTooltip data={{ ...data, traffic: undefined }} />);
    expect(screen.queryByText("Received")).not.toBeInTheDocument();
  });

  it("reveals traffic on keyboard focus and closes it on blur", async () => {
    const props = { id: "edge", data } as React.ComponentProps<
      typeof ResourceStatusEdge
    >;
    render(
      <svg>
        <ResourceStatusEdge {...props} />
      </svg>
    );
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    const trigger = screen.getByRole("img");
    fireEvent.focus(trigger);
    expect(await screen.findByRole("tooltip")).toHaveTextContent("2.37 kbps");
    fireEvent.blur(trigger);
    await waitFor(() =>
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument()
    );
  });

  it("reveals the same tooltip when hovering the connection", async () => {
    const props = { id: "edge", data } as React.ComponentProps<
      typeof ResourceStatusEdge
    >;
    render(
      <svg>
        <ResourceStatusEdge {...props} />
      </svg>
    );
    fireEvent.pointerMove(screen.getByRole("img"), { pointerType: "mouse" });
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Received");
  });
});
