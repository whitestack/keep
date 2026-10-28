"use client";

import {
  Icon,
  Tab,
  TabGroup,
  TabList,
  TabPanel,
  TabPanels,
} from "@tremor/react";
import { TopologyMap } from "./ui/map";
import { ApplicationsList } from "./ui/applications/applications-list";
import React, { useContext, useEffect, useState } from "react";
import { TopologySearchContext } from "./TopologySearchContext";
import { TopologyApplication, TopologyService } from "./model";
import { ArrowPathIcon } from "@heroicons/react/24/outline";
import { useApi } from "@/shared/lib/hooks/useApi";
import { toast } from "react-toastify";
import { TopologyFiltersValue } from "./topology-filter-panel";
import { getTopology, pullTopology } from "./api";


export function TopologyPageClient({
  applications,
  topologyServices,
}: {
  applications?: TopologyApplication[];
  topologyServices?: TopologyService[];
}) {
  const [tabIndex, setTabIndex] = useState(0);
  const { selectedObjectId } = useContext(TopologySearchContext);
  const api = useApi();

  const [topologyFilters, setTopologyFilters] =
    useState<TopologyFiltersValue>({
      vmNameRegex: "",
      hypervisorName: "",
      maxVmsPerHypervisor: "",
    });


  const handleFiltersChange = async (filters: TopologyFiltersValue) => {
    setTopologyFilters(filters);
  };



  const handlePullTopology = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      console.log("Pulling topology from providers...");
      console.log("API client:", api.getApiBaseUrl());
      console.log('Filters:', topologyFilters);
      // await pullTopology(api);
      toast.success("Topology pull initiated");
    } catch (error) {
      toast.error("Failed to pull topology");
      console.error("Failed to pull topology:", error);
    }
  };

  useEffect(() => {
    if (!selectedObjectId) {
      return;
    }
    setTabIndex(0);
  }, [selectedObjectId]);

  return (
    <TabGroup
      id="topology-tabs"
      className="flex flex-col"
      index={tabIndex}
      onIndexChange={setTabIndex}
    >
      <TabList className="mb-2">
        <Tab
          className="items-center"
        >
          Topology Map
        </Tab>
        <Tab className="items-center">Applications</Tab>
        <Tab
          className="items-center"
          icon={ArrowPathIcon}
          onClick={handlePullTopology}
        >
          Pull from providers</Tab>
      </TabList>
      <TabPanels className="flex-1 flex flex-col">
        <TabPanel className="h-[calc(100vh-10rem)]">
          <TopologyMap
            standalone
            topologyApplications={applications}
            topologyServices={topologyServices}
            isVisible={tabIndex === 0}
            filters={topologyFilters}
            onFiltersChange={handleFiltersChange}
          />
        </TabPanel>
        <TabPanel className="flex-1">
          <ApplicationsList applications={applications} />
        </TabPanel>
      </TabPanels>
    </TabGroup>
  );
}
