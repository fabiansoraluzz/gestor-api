// api/auth/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { loginPasswordSchema } from "../../lib/validate";
import { setRefreshCookie } from "../../lib/cookies";

function isPhone(identifier: string) {
  return !identifier.includes("@");
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = String(req.headers["content-type"] || "");
  if (!ct.includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { identifier, password, recordarme } = loginPasswordSchema.parse(raw);

    // Resolver email si viene teléfono
    let emailToUse = identifier;
    if (isPhone(identifier)) {
      const { data: prof, error: e1 } = await supabaseAdmin
        .from("profiles")
        .select("email")
        .eq("phone", identifier)
        .maybeSingle();
      if (e1 || !prof?.email) return res.status(401).json({ error: "Credenciales inválidas" });
      emailToUse = prof.email;
    }

    const supabase = supabaseServer();
    const { data, error } = await supabase.auth.signInWithPassword({
      email: emailToUse,
      password,
    });

    if (error || !data?.session || !data?.user) {
      const msg = (error?.message || "").toLowerCase();
      if (msg.includes("confirm")) {
        return res
          .status(403)
          .json({ error: "Debes confirmar tu correo antes de ingresar.", requiereConfirmacion: true });
      }
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
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
