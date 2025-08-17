// api/lib/pattern.ts
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

/** Genera salt + hash del patrón */
export function hashPattern(pattern: string) {
  const salt = randomBytes(16).toString("hex");
  const buf = scryptSync(pattern, salt, 64);       // Buffer
  const hash = buf.toString("hex");
  return { salt, hash };
}

/** Verifica un patrón contra (salt, hash) */
export function verifyPattern(pattern: string, salt: string, expectedHexHash: string) {
  const calc = scryptSync(pattern, salt, 64);      // Buffer
  const expected = Buffer.from(expectedHexHash, "hex");
  return timingSafeEqual(calc, expected);
}
