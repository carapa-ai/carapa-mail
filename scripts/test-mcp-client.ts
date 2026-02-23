import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

async function run() {
    const token = process.env.MCP_TOKEN;
    if (!token) {
        console.error("Please set MCP_TOKEN env variable");
        process.exit(1);
    }

    // carapamail MCP uses a single POST endpoint right now, but standard SDK expects SSE
    // We'll write a simple fetch wrapper for the custom stateless StreamableHTTP
    const mcpPort = process.env.MCP_PORT || '3477';
    const url = `http://localhost:${mcpPort}/mcp`;

    async function callMcpHelper(toolName: string, args: any) {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream',
                Authorization: `Bearer ${token}`
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'tools/call',
                params: {
                    name: toolName,
                    arguments: args
                }
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }

        const data = await response.json();
        if (data.error) {
            console.error(`\n[MCP Error] Tool '${toolName}' failed:`, data.error.message);
            return null;
        }

        return data.result;
    }

    console.log("Listing messages in INBOX...");
    const listResult = await callMcpHelper("carapamail_list_emails", {
        folder: "INBOX",
        limit: 3
    });

    if (!listResult || listResult.isError) {
        console.error("Failed to list messages or none returned.");
        if (listResult?.content) console.error(listResult.content[0].text);
        return;
    }

    const messagesText = listResult.content.find((c: any) => c.type === 'text')?.text;
    if (!messagesText || messagesText === "[]") {
        console.log("INBOX is empty.");
        return;
    }

    console.log("DEBUG: messagesText:", messagesText);
    const data = JSON.parse(messagesText);
    const messages = data.items || [];
    if (messages.length === 0) {
        console.log("INBOX is empty.");
        return;
    }

    const lastMsg = messages[0];
    if (!lastMsg || lastMsg.uid === undefined) {
        console.log("Failed to get valid message details.");
        return;
    }
    console.log(`\nFound latest email:`);
    console.log(`UID: ${lastMsg.uid}`);
    console.log(`From: ${lastMsg.from}`);
    console.log(`Subject: ${lastMsg.subject}`);

    console.log(`\nFetching strictly filtered body for UI ${lastMsg.uid} via MCP tool...`);
    const readResult = await callMcpHelper("carapamail_read_email", {
        folder: "INBOX",
        uid: lastMsg.uid
    });

    if (!readResult || readResult.isError) {
        console.log("\n❌ MCP AGENT ACCESS DENIED OR FAILED:");
        if (readResult?.content) {
            console.log(readResult.content[0].text);
        }
        return;
    }

    const bodyText = readResult.content.find((c: any) => c.type === 'text')?.text;
    console.log("\n✅ MCP AGENT ACCESS GRANTED. Content:");
    console.log(bodyText.substring(0, 500) + (bodyText.length > 500 ? "...\n[TRUNCATED]" : ""));
}

run().catch(err => {
    console.error("Fatal error:", err);
    process.exit(1);
});
