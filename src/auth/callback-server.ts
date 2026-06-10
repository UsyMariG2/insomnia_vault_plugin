/**
 * Hardened localhost callback server for the Authorization Code flow.
 *
 * Defensive properties (see THREAT_MODEL.md §"Callback server"):
 *   1. Binds to `127.0.0.1` only — no other host on the network can reach it.
 *   2. Accepts a single request, then closes. No long-lived listener.
 *   3. Only `GET /` is honored; everything else gets a 405 and the request is dropped.
 *   4. The callback MUST carry both `code` and `state`, and `state` MUST equal
 *      the value the plugin sent in /authorize. Mismatch → 400, flow fails.
 *   5. Hard timeout aborts the wait if no response arrives within
 *      `timeoutMs` (default 5 min).
 *
 * Returns `{ code }` once a valid callback is received. The browser is
 * redirected to `redirectAfter` (typically the OIDC info page) so the user
 * sees a friendly "you can close this tab" message rather than a JSON blob.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";
import { constantTimeEqual } from "../util/encoding";
import { debug, warn } from "../util/log";

export interface CallbackResult {
  code: string;
}

export interface CallbackServer {
  port: number;
  /** Resolves with the code once a valid callback arrives. Rejects on timeout or invalid state. */
  waitForCode(): Promise<CallbackResult>;
  /** Aborts the wait and tears down the server. Safe to call more than once. */
  close(): void;
}

export interface CallbackServerOptions {
  expectedState: string;
  /** Where the browser is redirected after success. `null` to render a plain text page. */
  redirectAfterSuccess?: string | null;
  /** Hard timeout in ms. Default: 5 minutes. */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

export async function startCallbackServer(options: CallbackServerOptions): Promise<CallbackServer> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let resolveCode: ((value: CallbackResult) => void) | null = null;
  let rejectCode: ((err: Error) => void) | null = null;
  const codePromise = new Promise<CallbackResult>((res, rej) => {
    resolveCode = res;
    rejectCode = rej;
  });

  let timer: NodeJS.Timeout | null = null;
  let settled = false;

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    handleRequest(req, res, options, (result, err) => {
      if (settled) return;
      if (err) {
        settled = true;
        clear();
        rejectCode?.(err);
        server.close();
        return;
      }
      if (result) {
        settled = true;
        clear();
        resolveCode?.(result);
        server.close();
      }
    });
  });

  server.on("error", (err: Error) => {
    if (settled) return;
    settled = true;
    clear();
    rejectCode?.(err);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address() as AddressInfo | null;
  if (!addr || typeof addr.port !== "number") {
    server.close();
    throw new Error("Failed to bind localhost callback server.");
  }
  debug(`Callback server listening on 127.0.0.1:${addr.port}.`);

  // The plugin executes in Insomnia's Electron renderer when "Allow elevated
  // access for plugins" is enabled, where globalThis.setTimeout is Chromium's
  // DOM API and returns a number, not a Node Timeout. Calling .unref() on the
  // result would throw "setTimeout(...).unref is not a function" and crash
  // every browser-based tag (the bug seen in 1.0.0-rc.1). The clear() helper
  // below explicitly cancels the timer in every success, error, and close
  // path, so the keep-event-loop-alive concern .unref() is meant to address
  // does not apply here.
  timer = setTimeout(() => {
    if (settled) return;
    settled = true;
    warn(`Callback server timed out after ${timeoutMs}ms without a valid callback.`);
    rejectCode?.(new Error(`Authentication timed out after ${Math.round(timeoutMs / 1000)}s.`));
    server.close();
  }, timeoutMs);

  const clear = (): void => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };

  return {
    port: addr.port,
    waitForCode: () => codePromise,
    close: () => {
      if (settled) return;
      settled = true;
      clear();
      rejectCode?.(new Error("Callback server was closed before a callback arrived."));
      server.close();
    },
  };
}

function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: CallbackServerOptions,
  done: (result: CallbackResult | null, err: Error | null) => void,
): void {
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    res.statusCode = 405;
    res.setHeader("Allow", "GET");
    res.end("Method Not Allowed");
    return;
  }

  let parsed: URL;
  try {
    parsed = new URL(req.url ?? "/", `http://127.0.0.1`);
  } catch {
    res.statusCode = 400;
    res.end("Bad Request");
    return;
  }

  if (parsed.pathname !== "/") {
    res.statusCode = 404;
    res.end("Not Found");
    return;
  }

  const code = parsed.searchParams.get("code");
  const state = parsed.searchParams.get("state");
  const errorParam = parsed.searchParams.get("error");

  if (errorParam) {
    const desc = parsed.searchParams.get("error_description") ?? "";
    res.statusCode = 400;
    res.end(`Authentication error from OIDC server: ${errorParam}`);
    done(null, new Error(`OIDC server returned error '${errorParam}'${desc ? `: ${desc}` : ""}.`));
    return;
  }

  if (!code || !state) {
    res.statusCode = 400;
    res.end("Missing `code` or `state` parameter.");
    done(null, new Error("Callback missing `code` or `state`."));
    return;
  }

  if (!constantTimeEqual(state, options.expectedState)) {
    res.statusCode = 400;
    res.end("State mismatch — this callback does not belong to this plugin instance.");
    done(null, new Error("Callback `state` did not match the value we sent — possible CSRF or stale browser tab."));
    return;
  }

  if (options.redirectAfterSuccess) {
    res.statusCode = 302;
    res.setHeader("Location", options.redirectAfterSuccess);
    res.end();
  } else {
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Authentication successful. You can close this tab and return to Insomnia.");
  }

  done({ code }, null);
}
