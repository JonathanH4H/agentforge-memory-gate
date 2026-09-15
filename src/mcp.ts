#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ScanRequestSchema, ScanResultSchema } from "./schemas.js";
import {
  HashMismatchError,
  IdempotencyConflictError,
  MemoryGateService,
} from "./scan.js";

export function createMcpServer(service = new MemoryGateService()) {
  const server = new McpServer({
    name: "memory-gate",
    version: "0.1.0",
  });

  server.registerTool(
    "memory_scan",
    {
      title: "Memory scan",
      description:
        "ASI06 heuristic write-path scan before persisting agent memory / RAG. Same JSON in/out as POST /v1/memory/scan. Not a formal MINJA proof.",
      inputSchema: ScanRequestSchema,
    },
    async (args) => {
      const parsed = ScanRequestSchema.safeParse(args);
      if (!parsed.success) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: "invalid_request",
                details: parsed.error.flatten(),
              }),
            },
          ],
        };
      }

      try {
        const result = ScanResultSchema.parse(service.scan(parsed.data));
        const text = JSON.stringify(result);
        return {
          content: [{ type: "text" as const, text }],
          structuredContent: result,
        };
      } catch (err) {
        if (err instanceof HashMismatchError) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "content_hash_mismatch",
                  expected: err.expected,
                }),
              },
            ],
          };
        }
        if (err instanceof IdempotencyConflictError) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: "idempotency_key_conflict" }),
              },
            ],
          };
        }
        throw err;
      }
    },
  );

  return { server, service };
}

async function main() {
  const { server } = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

const isDirect =
  process.argv[1] &&
  (process.argv[1].endsWith("mcp.ts") || process.argv[1].endsWith("mcp.js"));

if (isDirect) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
