import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { NodeProps } from "@xyflow/react";
import type { ServiceNodeType } from "@/app/(keep)/topology-v2/model/models";
import { ServiceNode } from "@/app/(keep)/topology-v2/ui/map/service-node";

jest.mock("@xyflow/react", () => ({
  Handle: () => null,
  Position: { Left: "left", Right: "right" },
}));
jest.mock("@/components/ui", () => ({ DynamicImageProviderIcon: () => null }));

const props: NodeProps<ServiceNodeType> = {
  id: "vm-id",
  type: "service",
  dragging: false,
  draggable: true,
  selectable: true,
  deletable: true,
  isConnectable: true,
  zIndex: 0,
  positionAbsoluteX: 0,
  positionAbsoluteY: 0,
  data: {
    id: "vm-id",
    service: "vm-id",
    display_name: "test-vm",
    category: "instance",
    description: "Status: ACTIVE",
    applications: [],
    application_ids: [],
    dependencies: [],
    is_manual: false,
    topologyMutator: jest.fn(),
  },
  selected: false,
};

function rect(x: number, y: number, width: number, height: number): DOMRect {
  return {
    x,
    y,
    width,
    height,
    left: x,
    top: y,
    right: x + width,
    bottom: y + height,
    toJSON: () => ({}),
  };
}

describe("resource tooltip positioning", () => {
  let nodeRect: DOMRect;
  beforeEach(() => {
    nodeRect = rect(20, 300, 260, 160);
    jest
      .spyOn(document.documentElement, "clientWidth", "get")
      .mockReturnValue(1000);
    jest
      .spyOn(document.documentElement, "clientHeight", "get")
      .mockReturnValue(800);
    jest
      .spyOn(HTMLElement.prototype, "getBoundingClientRect")
      .mockImplementation(function (this: HTMLElement) {
        if (this === document.documentElement) return rect(0, 0, 1000, 800);
        if (this.classList.contains("z-50")) return rect(0, 0, 400, 240);
        if (this.classList.contains("h-full")) return nodeRect;
        return rect(0, 0, 0, 0);
      });
    jest
      .spyOn(HTMLElement.prototype, "offsetWidth", "get")
      .mockImplementation(function (this: HTMLElement) {
        return this.classList.contains("z-50")
          ? 400
          : this.classList.contains("h-full")
            ? 260
            : 0;
      });
    jest
      .spyOn(HTMLElement.prototype, "offsetHeight", "get")
      .mockImplementation(function (this: HTMLElement) {
        return this.classList.contains("z-50")
          ? 240
          : this.classList.contains("h-full")
            ? 160
            : 0;
      });
  });
  afterEach(() => jest.restoreAllMocks());

  it.each([
    [20, 300, "right"],
    [720, 300, "left"],
    [370, 20, "bottom"],
    [370, 620, "top"],
  ])("chooses %s/%s -> %s using available screen space", async (x, y, side) => {
    nodeRect = rect(Number(x), Number(y), 260, 160);
    render(<ServiceNode {...props} />);
    fireEvent.mouseEnter(
      screen.getByTitle("test-vm").parentElement!.parentElement!
    );
    await waitFor(() => {
      const popup = document.querySelector("[data-placement]");
      expect(popup).toHaveAttribute("data-placement", side);
      expect(popup).toHaveStyle({ visibility: "visible" });
    });
    expect(
      screen.getByRole("heading", { name: "test-vm" })
    ).toBeInTheDocument();
  });

  it("repositions an open tooltip when the node moves", async () => {
    render(<ServiceNode {...props} />);
    const node = screen.getByTitle("test-vm").parentElement!.parentElement!;
    fireEvent.mouseEnter(node);
    await waitFor(() =>
      expect(document.querySelector("[data-placement]")).toHaveAttribute(
        "data-placement",
        "right"
      )
    );
    nodeRect = rect(720, 300, 260, 160);
    await waitFor(() =>
      expect(document.querySelector("[data-placement]")).toHaveAttribute(
        "data-placement",
        "left"
      )
    );
    fireEvent.mouseLeave(node);
    expect(document.querySelector("[data-placement]")).not.toBeInTheDocument();
  });
});
