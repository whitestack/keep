import { TopologyApplication, TopologyService } from "../model/models";
import { ApiClient } from "@/shared/api";


export function buildTopologyUrl({
  providerIds,
  services,
  environment,
  vmNameRegex,
  hypervisorName,
  maxVmsPerHypervisor,
}: {
  providerIds?: string[];
  services?: string[];
  environment?: string;
  vmNameRegex?: string;
  hypervisorName?: string;
  maxVmsPerHypervisor?: string;
}) {
  const baseUrl = "/topology/whitecloud";
  const params = new URLSearchParams();

  if (providerIds?.length) {
    params.append("provider_ids", providerIds.join(","));
  }

  if (services?.length) {
    params.append("services", services.join(","));
  }

  if (environment) {
    params.append("environment", environment);
  }

  if (vmNameRegex?.trim()) {
    params.append("vm_name_regex", vmNameRegex.trim());
  }

  if (hypervisorName?.trim()) {
    params.append("hypervisor_name", hypervisorName.trim());
  }

  console.log("maxVmsPerHypervisor", maxVmsPerHypervisor);
  if (maxVmsPerHypervisor) {
    params.append(
      "max_vms_per_hypervisor",
      String(maxVmsPerHypervisor)
    );
  }

  const query = params.toString();
  return query ? `${baseUrl}?${query}` : baseUrl;
}


export async function getApplications(api: ApiClient) {
  const url = `/topology/applications`;
  return await api.get<TopologyApplication[]>(url);
}


export async function getTopology(
  api: ApiClient,
  {
    providerIds,
    services,
    environment,
    vmNameRegex,
    hypervisorName,
    maxVmsPerHypervisor,
  }: {
    providerIds?: string[];
    services?: string[];
    environment?: string;
    vmNameRegex?: string;
    hypervisorName?: string;
    maxVmsPerHypervisor?: string;
  }
) {
  const url = buildTopologyUrl({
    providerIds,
    services,
    environment,
    vmNameRegex,
    hypervisorName,
    maxVmsPerHypervisor,
  });

  return await api.get<TopologyService[]>(url);
}


export async function pullTopology(api: ApiClient) {
  return await api.post("/topology/pull");
}
