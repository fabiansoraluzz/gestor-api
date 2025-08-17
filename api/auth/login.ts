// api/auth/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer } from "../../lib/supabase";
import { loginSchema, type LoginInput } from "../../lib/validate";
import { setRefreshCookie } from "../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const body = loginSchema.parse(raw) as LoginInput;

    // --- Variante A: email + password (activa hoy)
    if ("password" in body) {
      const { email, password, recordarme } = body;
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
        data.user.email?.split("@")[0] ??
        "Usuario";

      return res.status(200).json({
        usuarioId: data.user.id,
        email: data.user.email,
        nombre,
        accessToken: data.session.access_token,
        expiresIn: data.session.expires_in,
        tokenType: data.session.token_type,
      });
    }

    // --- Variante B: email + pattern (planificada)
    // Aquí validaremos el patrón contra la tabla de patrones y
    // generaremos sesión. Lo dejamos explícito por ahora:
    if ("pattern" in body) {
      return res
        .status(501)
        .json({ error: "Inicio con patrón aún no habilitado. Usa email + contraseña de momento." });
    }

    return res.status(400).json({ error: "Solicitud inválida" });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
