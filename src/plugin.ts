/**
 * Insomnia plugin entry point.
 *
 * Insomnia looks at `module.exports.templateTags` (and other extension points)
 * after `require()`ing the package's `main`. Keep this file as thin as
 * possible — all logic lives in `src/tags/*` and `src/auth/*`.
 */

import { uuPersonPlus4uOidcToken } from "./tags/uu-person-token";
import { uuPersonCustomOidcToken } from "./tags/uu-person-custom-token";
import { uuEePlus4uOidcToken } from "./tags/uu-ee-token";
import type { TemplateTag } from "./tags/types";

export const templateTags: TemplateTag[] = [
  uuPersonPlus4uOidcToken,
  uuPersonCustomOidcToken,
  uuEePlus4uOidcToken,
];

module.exports = { templateTags };
