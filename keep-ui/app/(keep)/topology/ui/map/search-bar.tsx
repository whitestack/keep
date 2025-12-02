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



export function ServiceSearchBar<T>() {
    const [inputValue, setInputValue] = useState("");
    const [filteredOptions, setFilteredOptions] = useState<Option<T>[]>([]);
    const [isOpen, setIsOpen] = useState(false);
    const [focusedIndex, setFocusedIndex] = useState(-1);
    const wrapperRef = useRef<HTMLDivElement | null>(null);
    const inputRef = useRef<HTMLInputElement | null>(null);
    const listRef = useRef<HTMLUListElement | null>(null);
    const { filter, setFilter } = useTopologyFilters();

    
    const { topologyData } = useTopology();

    
    
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setInputValue(value);
        setFilter(value)
    };
    
 
    return (
        <>
        <TextInput
            ref={inputRef}
            value={inputValue}
            onChange={handleInputChange}
            placeholder={'busqueda'}
            aria-autocomplete="list"
            aria-haspopup="listbox"
            aria-expanded={isOpen}
            aria-activedescendant={
            focusedIndex >= 0 ? `option-${focusedIndex}` : undefined
            }
        />
        </>
    );
}
