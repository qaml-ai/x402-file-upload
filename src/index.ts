import { Hono } from "hono";
import { cdpPaymentMiddleware } from "x402-cdp";

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const DEFAULT_TTL = 3600; // 1 hour

const app = new Hono<{ Bindings: Env }>();

app.use(
  cdpPaymentMiddleware(
    (env) => ({
      "POST /": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network: "eip155:8453",
            payTo: env.SERVER_ADDRESS as `0x${string}`,
          },
        ],
        description:
          "Upload a file and get a temporary signed URL. Send raw file body with Content-Type header. Returns a URL valid for 1 hour.",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            info: {
              input: {
                type: "http",
                method: "POST",
                bodyType: "raw",
                body: {
                  input: {
                    type: "string",
                    description:
                      "Upload a raw file as the request body. Set Content-Type to the file's MIME type. Optionally set X-Filename header.",
                    required: true,
                  },
                },
              },
              output: { type: "json" },
            },
            schema: {
              properties: {
                input: {
                  properties: { method: { type: "string", enum: ["POST"] } },
                  required: ["method"],
                },
              },
            },
          },
        },
      },
    })
  )
);

/** HMAC-sign a message with the signing secret */
async function sign(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Verify an HMAC signature */
async function verify(
  secret: string,
  message: string,
  signature: string
): Promise<boolean> {
  const expected = await sign(secret, message);
  return expected === signature;
}

// Upload: stream raw body to R2, return signed URL
app.post("/", async (c) => {
  const body = c.req.raw.body;
  if (!body) {
    return c.json({ error: "Empty request body" }, 400);
  }

  const contentType =
    c.req.header("content-type") || "application/octet-stream";
  const filename = c.req.header("x-filename") || null;
  const contentLength = parseInt(c.req.header("content-length") || "0", 10);

  if (contentLength > MAX_FILE_SIZE) {
    return c.json(
      { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB` },
      413
    );
  }

  const id = crypto.randomUUID();
  const expires = Math.floor(Date.now() / 1000) + DEFAULT_TTL;

  // Stream directly to R2 — never loads full file into worker memory
  await c.env.FILES.put(`tmp/${id}`, body, {
    httpMetadata: { contentType },
    customMetadata: {
      expires: String(expires),
      ...(filename ? { filename } : {}),
    },
  });

  const token = await sign(c.env.SIGNING_SECRET, `${id}:${expires}`);
  const baseUrl = new URL(c.req.url).origin;
  const url = `${baseUrl}/${id}?token=${token}&expires=${expires}`;

  return c.json({
    id,
    url,
    content_type: contentType,
    expires_at: new Date(expires * 1000).toISOString(),
    ...(filename ? { filename } : {}),
  });
});

// Download: verify token, serve file from R2
app.get("/:id", async (c) => {
  const id = c.req.param("id");
  const token = c.req.query("token");
  const expiresStr = c.req.query("expires");

  if (!token || !expiresStr) {
    return c.json({ error: "Missing token or expires parameter" }, 401);
  }

  const expires = parseInt(expiresStr, 10);
  if (Date.now() / 1000 > expires) {
    return c.json({ error: "URL has expired" }, 410);
  }

  const valid = await verify(c.env.SIGNING_SECRET, `${id}:${expires}`, token);
  if (!valid) {
    return c.json({ error: "Invalid token" }, 403);
  }

  const obj = await c.env.FILES.get(`tmp/${id}`);
  if (!obj) {
    return c.json({ error: "File not found or expired" }, 404);
  }

  return new Response(obj.body, {
    headers: {
      "Content-Type":
        obj.httpMetadata?.contentType || "application/octet-stream",
      "Cache-Control": "private, max-age=3600",
      ...(obj.customMetadata?.filename
        ? {
            "Content-Disposition": `inline; filename="${obj.customMetadata.filename}"`,
          }
        : {}),
    },
  });
});

// Info endpoint (free)
app.get("/", (c) => {
  return c.json({
    service: "x402-file-upload",
    description:
      "Upload files and get temporary signed URLs. POST raw file body with Content-Type header. URLs expire after 1 hour.",
    price: "$0.001 per upload (Base mainnet)",
    maxFileSize: "100MB",
  });
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext) {
    const now = Math.floor(Date.now() / 1000);
    let cursor: string | undefined;
    let deleted = 0;

    do {
      const listed = await env.FILES.list({ prefix: "tmp/", cursor, limit: 500 });
      const toDelete: string[] = [];

      for (const obj of listed.objects) {
        const expires = parseInt(obj.customMetadata?.expires || "0", 10);
        if (expires > 0 && now > expires) {
          toDelete.push(obj.key);
        }
      }

      if (toDelete.length > 0) {
        await env.FILES.delete(toDelete);
        deleted += toDelete.length;
      }

      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor);

    console.log(`Cleanup: deleted ${deleted} expired files`);
  },
};
