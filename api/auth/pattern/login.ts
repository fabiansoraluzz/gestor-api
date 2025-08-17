import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../../lib/cors";
import { supabaseAdmin } from "../../../lib/supabase";
import { patternLoginSchema } from "../../../lib/validate";
import { verifyPattern } from "../../../lib/pattern";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, pattern } = patternLoginSchema.parse(body);

    const { data, error } = await supabaseAdmin
      .from("auth_patterns")
      .select("salt, hash")
      .eq("email", email)
      .single();

    if (error || !data) return res.status(401).json({ error: "Patrón no registrado" });

    const ok = verifyPattern(pattern, data.salt, data.hash);
    if (!ok) return res.status(401).json({ error: "Patrón inválido" });

    // TODO: canjear por sesión real de Supabase (OTP o magic link server-side)
    return res.status(501).json({
      ok: true,
      message: "Patrón válido. Falta canjear por sesión de Supabase.",
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
