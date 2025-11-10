'use server';

import {
  CopilotRuntime,
  OpenAIAdapter,
  copilotRuntimeNextJSAppRouterEndpoint,
} from "@copilotkit/runtime";
import { NextRequest } from "next/server";

export const POST = async (req: NextRequest) => {
  const { default: OpenAI } = await import("openai");

  const openai = new OpenAI({
    organization: process.env.OPEN_AI_ORGANIZATION_ID,
    apiKey: process.env.OPEN_AI_API_KEY,
  });

  const serviceAdapter = new OpenAIAdapter({
    openai,
    model: process.env.OPENAI_MODEL_NAME || "gpt-4o-mini",
  });

  const runtime = new CopilotRuntime();

  const { handleRequest } = copilotRuntimeNextJSAppRouterEndpoint({
    runtime,
    serviceAdapter,
    endpoint: "/api/copilotkit",
  });

  return await handleRequest(req);
};
