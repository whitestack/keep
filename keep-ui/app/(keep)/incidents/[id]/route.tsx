import { redirect } from "next/navigation";

type PageProps = {
  params: Promise<{ id: string }>;
  searchParams?: Promise<{ [key: string]: string | string[] | undefined }>;
};

// This is just a redirect from legacy route
export async function GET(
  request: Request,
  props: { params: Promise<{ id: string }> }
) {
  redirect(`/incidents/${(await props.params).id}/alerts`);
}
