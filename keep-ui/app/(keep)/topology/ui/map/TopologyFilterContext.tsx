"use client"
import React, { useEffect, useState, useRef, createContext,useContext, ReactNode } from "react";
import { TextInput } from "@/components/ui";
import {
  useTopology
} from "@/app/(keep)/topology/model";

export type Option<T> = {
  label: string;
  value: T;
};
type TopologyFilterContextType = {
  filter: string;
  setFilter: (value: string) => void;
};

// -------------------------
// CONTEXT
// -------------------------
const TopologyFilterContext = createContext<TopologyFilterContextType | null>(
  null
);

// -------------------------
// PROVIDER
// -------------------------
export function TopologyFilterProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [filter, setFilter] = useState("");

  return (
    <TopologyFilterContext.Provider value={{ filter, setFilter }}>
      {children}
    </TopologyFilterContext.Provider>
  );
}

export function useTopologyFilters() {
  const ctx = useContext(TopologyFilterContext);
  if (!ctx) {
    throw new Error(
      "useTopologyFilters must be used inside a <TopologyFilterProvider>"
    );
  }
  return ctx;
}
