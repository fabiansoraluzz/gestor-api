// api/auth/pattern-set.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer } from "../../lib/supabase";
import { setPatternSchema } from "../../lib/validate";
import { cors } from "../../lib/cors";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS / Preflight
  if (cors(req, res)) return;

  if (req.method !== "POST") return res.status(405).end();

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sin token" });

  const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
  const { pattern } = setPatternSchema.parse(body);

  const supabase = supabaseServer(token);
  const { error } = await supabase.rpc("set_my_pattern", { p_plain: pattern });
  if (error) return res.status(400).json({ error: error.message });

  return res.status(204).end();
}
