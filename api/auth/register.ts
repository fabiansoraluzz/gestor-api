import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer } from "../../lib/supabase";
import { registerSchema } from "../../lib/validate";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body ?? {};
    const { nombreCompleto, email, password } = registerSchema.parse(body);

    const supabase = supabaseServer();
    const { data, error } = await supabase.auth.signUp({
      email, password,
      options: { data: { full_name: nombreCompleto } }
    });

    if (error) return res.status(400).json({ error: error.message });

    return res.status(201).json({
      usuarioId: data.user?.id ?? null,
      requiereConfirmacion: !data.session,
      accessToken: data.session?.access_token ?? null,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
