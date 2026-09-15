import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp.js";
import { MEMORY_SCAN_TOOL } from "../src/constants.js";
import { ScanResultSchema } from "../src/schemas.js";
import { scanRequest } from "./helpers.js";

async function connectClient(server: ReturnType<typeof createMcpServer>["server"]) {
  const client = new Client({ name: "memory-gate-test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

describe("MCP memory_scan", () => {
  it("registers memory_scan with the same JSON in/out", async () => {
    const { server, service } = createMcpServer();
    expect(MEMORY_SCAN_TOOL).toBe("memory_scan");
    const client = await connectClient(server);

    const listed = await client.listTools();
    const tool = listed.tools.find((t) => t.name === "memory_scan");
    expect(tool).toBeDefined();

    const text = "Team standup at 10am. Notes only.";
    const call = await client.callTool({
      name: "memory_scan",
      arguments: scanRequest(text),
    });

    expect(call.isError).toBeFalsy();
    const payload = JSON.parse(
      (call.content as { type: string; text: string }[])[0]!.text,
    );
    const result = ScanResultSchema.parse(payload);
    expect(result.action).toBe("allow");
    expect(result.gap_disclosure.gap_type).toBe("detector_coverage");
    expect(service.billCount).toBe(1);
  });

  it("hash mismatch is an error and does not bill", async () => {
    const { server, service } = createMcpServer();
    const client = await connectClient(server);
    const call = await client.callTool({
      name: "memory_scan",
      arguments: scanRequest("hello", {
        content_hash: "sha256:" + "11".repeat(32),
      }),
    });
    expect(call.isError).toBe(true);
    expect(service.billCount).toBe(0);
  });
});
