// api/auth/pattern-login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { patternLoginSchema } from "../../lib/validate";
import { cors } from "../../lib/cors";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS / Preflight
  if (cors(req, res)) return;

  if (req.method !== "POST") return res.status(405).end();

  const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
  const { email, pattern } = patternLoginSchema.parse(body);

  // 1) Verificar patrón (RPC pública)
  const supabase = supabaseServer();
  const { data: profileId, error } = await supabase.rpc("verify_pattern", {
    p_email: email,
    p_plain: pattern,
  });

  if (error) return res.status(400).json({ error: error.message });
  if (!profileId) return res.status(401).json({ error: "Patrón inválido o bloqueado" });

  // 2) Generar Magic Link para crear sesión
  const { data: link, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
    type: "magiclink",
    email,
  });

  const loginUrl = link?.properties?.action_link;
  if (linkErr || !loginUrl) {
    return res.status(500).json({ error: linkErr?.message ?? "No se pudo generar el enlace de sesión" });
  }

  return res.status(200).json({ loginUrl });
}
