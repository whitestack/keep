import { MarkerType } from "@xyflow/react";

export const nodeWidth = 260;
export const nodeHeight = 128;

// Edge No Hover
export const edgeLabelBgStyleNoHover = {
  strokeWidth: 1,
  fill: "#ffffff",
  stroke: "#cbd5e1",
};
export const edgeLabelBgBorderRadiusNoHover = 10;
export const edgeLabelBgPaddingNoHover: [number, number] = [10, 5];
export const edgeMarkerEndNoHover = {
  type: MarkerType.ArrowClosed,
};
