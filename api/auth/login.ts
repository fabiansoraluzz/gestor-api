// api/auth/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer } from "../../lib/supabase";
import { loginSchema } from "../../lib/validate";
import { setRefreshCookie } from "../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, password, recordarme } = loginSchema.parse(body);

    const supabase = supabaseServer();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    if (error || !data?.session || !data?.user) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    if (data.session.refresh_token) {
      setRefreshCookie(res, data.session.refresh_token, Boolean(recordarme));
    }

    const nombre =
      (data.user.user_metadata?.full_name as string | undefined) ??
      (data.user.user_metadata?.name as string | undefined) ??
      (data.user.email?.split("@")[0]) ??
      "Usuario";

    return res.status(200).json({
      usuarioId: data.user.id,
      email: data.user.email,
      nombre, // 👈 nuevo
      accessToken: data.session.access_token,
      expiresIn: data.session.expires_in,
      tokenType: data.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
