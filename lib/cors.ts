// api/lib/cors.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";

const ALLOWED = (process.env.CORS_ORIGINS ?? "http://localhost:5173")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

export function cors(req: VercelRequest, res: VercelResponse): boolean {
  const origin = req.headers.origin ?? "";

  if (ALLOWED.includes(origin) || ALLOWED.includes("*")) {
    // ⚠️ Con credenciales, Access-Control-Allow-Origin no puede ser '*'
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-vercel-protection-bypass"
  );

  // ✅ siempre true (o si prefieres, condiciona con CORS_CREDENTIALS === "true")
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return true;
  }
  return false;
}
