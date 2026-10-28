"use client";

import { useState } from "react";
import { Button } from "@tremor/react";
import { showErrorToast } from "@/shared/ui";

export type TopologyFiltersValue = {
  vmNameRegex: string;
  hypervisorName: string;
  maxVmsPerHypervisor: string;
};

type TopologyFiltersProps = {
  value: TopologyFiltersValue;
  onApply: (filters: TopologyFiltersValue) => void;
};

const emptyFilters: TopologyFiltersValue = {
  vmNameRegex: "",
  hypervisorName: "",
  maxVmsPerHypervisor: "",
};

export function TopologyFilters({
  value,
  onApply,
}: TopologyFiltersProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [filters, setFilters] = useState(value);

  const activeCount = [
    value.vmNameRegex,
    value.hypervisorName,
    value.maxVmsPerHypervisor,
  ].filter((item) => item.trim() !== "").length;

  const updateFilter = (
    field: keyof TopologyFiltersValue,
    newValue: string
  ) => {
    setFilters((prev) => ({ ...prev, [field]: newValue }));
  };

  const handleApply = () => {
    if (filters.vmNameRegex.trim()) {
      try {
        new RegExp(filters.vmNameRegex);
      } catch {
        showErrorToast(
          new Error("Invalid regular expression"),
          "Invalid VM name regex"
        );
        return;
      }
    }

    const limit = filters.maxVmsPerHypervisor.trim();

    if (
      limit &&
      (!Number.isInteger(Number(limit)) || Number(limit) < 1)
    ) {
      showErrorToast(
        new Error("The limit must be a positive integer"),
        "Invalid VM limit"
      );
      return;
    }

    onApply(filters);
    setIsOpen(false);
  };

  const inputClass =
    "w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100";

  return (
    <div className="relative shrink-0">
      <Button
        color="gray"
        variant="secondary"
        size="md"
        onClick={() => setIsOpen((open) => !open)}
      >
        Filters{activeCount > 0 ? ` (${activeCount})` : ""}
      </Button>

      {isOpen && (
        <div className="absolute right-0 top-full z-50 mt-2 w-80 rounded-lg border border-gray-200 bg-white p-4 shadow-xl dark:border-gray-700 dark:bg-gray-900">
          <h3 className="mb-4 text-sm font-semibold text-gray-900 dark:text-gray-100">
            Topology filters
          </h3>

          <div className="space-y-4">
            <div>
              <label htmlFor="vm-name-regex" className="mb-1 block text-sm">
                VM name regex
              </label>
              <input
                id="vm-name-regex"
                className={inputClass}
                value={filters.vmNameRegex}
                placeholder="e.g. ^vm-prod-.*"
                onChange={(e) =>
                  updateFilter("vmNameRegex", e.target.value)
                }
              />
            </div>

            <div>
              <label htmlFor="hypervisor-name" className="mb-1 block text-sm">
                Hypervisor name
              </label>
              <input
                id="hypervisor-name"
                className={inputClass}
                value={filters.hypervisorName}
                placeholder="e.g. EPYC04"
                onChange={(e) =>
                  updateFilter("hypervisorName", e.target.value)
                }
              />
            </div>

            <div>
              <label
                htmlFor="max-vms-per-hypervisor"
                className="mb-1 block text-sm"
              >
                Max VMs per hypervisor
              </label>
              <input
                id="max-vms-per-hypervisor"
                type="number"
                min={1}
                step={1}
                className={inputClass}
                value={filters.maxVmsPerHypervisor}
                placeholder="No limit"
                onChange={(e) =>
                  updateFilter("maxVmsPerHypervisor", e.target.value)
                }
              />
            </div>
          </div>

          <div className="mt-5 flex justify-end gap-2 border-t border-gray-200 pt-3 dark:border-gray-700">
            <Button
              color="gray"
              variant="secondary"
              size="sm"
              onClick={() => {
                setFilters(emptyFilters);
                onApply(emptyFilters);
              }}
            >
              Clear
            </Button>

            <Button
              color="orange"
              variant="primary"
              size="sm"
              onClick={handleApply}
            >
              Apply filters
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}