import { TopologySearchProvider } from "@/app/(keep)/topology-v2/TopologySearchContext";

export default function Layout({ children }: { children: any }) {
  return <TopologySearchProvider>{children}</TopologySearchProvider>;
}
