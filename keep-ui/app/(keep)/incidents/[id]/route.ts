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

export function GET(
  request: NextRequest,
  context: { params: { id: string } }
) {
  const id = context.params.id;
  return redirect(`/incidents/${id}/alerts`);
}
