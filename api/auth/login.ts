import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer } from "../../lib/supabase";
import { loginSchema } from "../../lib/validate";
import { setRefreshCookie } from "../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Preflight CORS (por si el front lo envía)
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")   return res.status(405).end();

  // Requerir JSON
  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, password, recordarme } = loginSchema.parse(body);

    const supabase = supabaseServer();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    // No revelar si es email no confirmado / usuario no existe / pass errónea
    if (error || !data?.session || !data?.user) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Cookie persistente solo si "Recordarme" está activo
    if (data.session.refresh_token) {
      setRefreshCookie(res, data.session.refresh_token, Boolean(recordarme));
    }

    return res.status(200).json({
      usuarioId: data.user.id,
      email: data.user.email,
      accessToken: data.session.access_token,
      expiresIn: data.session.expires_in,
      tokenType: data.session.token_type
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
