import { NextRequest } from "next/server";

export const POST = async (req: NextRequest) => {
  if (process.env.COPILOT_DISABLED === "true") {
    return new Response("Copilot disabled", { status: 503 });
  }

  const { CopilotRuntime, OpenAIAdapter, copilotRuntimeNextJSAppRouterEndpoint } =
    await import("@copilotkit/runtime");
  const OpenAI = (await import("openai")).default;

  const openai = new OpenAI({
    organization: process.env.OPEN_AI_ORGANIZATION_ID,
    apiKey: process.env.OPEN_AI_API_KEY,
  });

  const serviceAdapter = new OpenAIAdapter({ openai });
  const runtime = new CopilotRuntime();

  const { handleRequest } = copilotRuntimeNextJSAppRouterEndpoint({
    runtime,
    serviceAdapter,
    endpoint: "/api/copilotkit",
  });

  return handleRequest(req);
};
