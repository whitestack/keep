// import { redirect } from "next/navigation";

// type PageProps = {
//   params: Promise<{ id: string }>;
//   searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
// };

// // This is just a redirect from legacy route
// export async function GET(request: Request, props: PageProps) {
//   redirect(`/incidents/${(await props.params).id}/alerts`);
// }

import { NextRequest } from "next/server";
import { redirect } from "next/navigation";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  redirect(`/incidents/${params.id}/alerts`);
}
