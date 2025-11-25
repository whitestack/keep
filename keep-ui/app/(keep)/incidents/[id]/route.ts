// import { redirect } from "next/navigation";

// type PageProps = {
//   params: Promise<{ id: string }>;
//   searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
// };

// // This is just a redirect from legacy route
// export async function GET(request: Request, props: PageProps) {
//   redirect(`/incidents/${(await props.params).id}/alerts`);
// }

import { NextRequest, NextResponse } from "next/server";
import { redirect } from "next/server"; // <-- ESTA ES LA CORRECTA

export function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const id = params.id;
  return redirect(`/incidents/${id}/alerts`);
}
