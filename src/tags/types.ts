/**
 * Minimal typing for the slice of the Insomnia plugin API we touch.
 * Kept here so the rest of the codebase can be written without importing any
 * Insomnia-specific package (it isn't published as types).
 */

export interface InsomniaPromptOptions {
  label?: string;
  defaultValue?: string;
  inputType?: "text" | "password";
}

export interface InsomniaContextApp {
  prompt(title: string, options?: InsomniaPromptOptions): Promise<string | undefined>;
  alert?(title: string, message: string): Promise<void>;
}

export interface InsomniaContextMeta {
  workspaceId?: string;
  requestId?: string;
}

export interface InsomniaContext {
  app: InsomniaContextApp;
  meta?: InsomniaContextMeta;
  context?: {
    getPurpose?(): string;
  };
}

export type TemplateTagRun = (context: InsomniaContext, ...args: unknown[]) => Promise<string>;

export interface TemplateTagArg {
  displayName: string;
  type: "string" | "boolean" | "enum" | "number";
  defaultValue?: string | boolean | number;
  placeholder?: string;
  help?: string;
  options?: { displayName: string; value: string }[];
}

export interface TemplateTag {
  name: string;
  displayName: string;
  description: string;
  args: TemplateTagArg[];
  run: TemplateTagRun;
}
