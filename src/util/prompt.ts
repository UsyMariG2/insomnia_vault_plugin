/**
 * Minimal terminal prompt helpers used by the CLI (migration tool, etc.).
 *
 * Avoids the legacy `read` dependency. Reads from stdin with raw mode so the
 * password isn't echoed. If stdin is not a TTY (CI, pipes), falls back to a
 * line read so the tool is still scriptable.
 */

import { createInterface } from "node:readline";
import { stdin, stdout } from "node:process";

export async function promptText(question: string): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    return await new Promise<string>((resolve) => {
      rl.question(question, (answer) => resolve(answer));
    });
  } finally {
    rl.close();
  }
}

export async function promptPassword(question: string): Promise<string> {
  if (!stdin.isTTY) {
    return promptText(question);
  }
  return new Promise<string>((resolve, reject) => {
    stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    let buffer = "";
    const onData = (chunk: string): void => {
      for (const char of chunk) {
        const code = char.charCodeAt(0);
        if (char === "\n" || char === "\r" || code === 4) {
          stdout.write("\n");
          cleanup();
          resolve(buffer);
          return;
        }
        if (code === 3) {
          cleanup();
          reject(new Error("Cancelled by user."));
          return;
        }
        if (code === 127 || code === 8) {
          buffer = buffer.slice(0, -1);
          continue;
        }
        buffer += char;
      }
    };

    const cleanup = (): void => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
    };

    stdin.on("data", onData);
  });
}
