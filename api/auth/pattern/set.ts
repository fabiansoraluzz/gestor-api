import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../../lib/supabase";
import { patternSetSchema, patternLoginSchema } from "../../../lib/validate";
import { hashPattern, verifyPattern } from "../../../lib/pattern";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!bearer) return res.status(401).json({ error: "Sin token" });

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : req.body ?? {};
    const { pattern } = patternSetSchema.parse(raw);

    const anon = supabaseServer();
    const { data: u, error: eUser } = await anon.auth.getUser(bearer);
    if (eUser || !u?.user) return res.status(401).json({ error: "Token inválido" });

    const { salt, hash } = hashPattern(pattern);
    const { error } = await supabaseAdmin.from("auth_patterns").upsert({
      user_id: u.user.id,
      email: u.user.email!,
      salt, hash
    });
    if (error) return res.status(400).json({ error: error.message });

    return res.status(204).end();
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
