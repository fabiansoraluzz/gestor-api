// api/lib/cors.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";

const ALLOWED = (process.env.CORS_ORIGINS ?? "http://localhost:5173")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

/**
 * Aplica CORS y maneja el preflight.
 * Devuelve true si ya respondió (OPTIONS).
 */
export function cors(req: VercelRequest, res: VercelResponse): boolean {
  const origin = req.headers.origin ?? "";

  // Permite origen específico (no usar * si vas con credenciales)
  if (ALLOWED.includes(origin) || ALLOWED.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
    res.setHeader("Vary", "Origin");
  }

  // Métodos y headers permitidos
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-vercel-protection-bypass"
  );

  // Activa si vas a usar cookies / credenciales cross-site
  if (process.env.CORS_CREDENTIALS === "true") {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  // Preflight
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return true;
  }
  return false;
}
