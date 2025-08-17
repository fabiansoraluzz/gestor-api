// api/auth/pattern/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../../lib/supabase";
import { patternLoginSchema } from "../../../lib/validate";
import { verifyPattern } from "../../../lib/pattern";
import { setRefreshCookie } from "../../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, pattern, recordarme } = patternLoginSchema.parse(raw);

    if (!email) {
      return res.status(400).json({ error: "Falta email (por ahora el login por patrón requiere email)" });
    }

    // 1) Traer salt+hash del patrón
    const { data: row, error: eRow } = await supabaseAdmin
      .from("auth_patterns")
      .select("salt, hash")
      .eq("email", email)
      .maybeSingle();

    if (eRow) return res.status(400).json({ error: eRow.message });
    if (!row?.salt || !row?.hash) return res.status(401).json({ error: "Patrón no configurado" });

    // 2) Verificar patrón
    const ok = verifyPattern(pattern, row.salt, row.hash);
    if (!ok) return res.status(401).json({ error: "Patrón inválido" });

    // 3) Generar OTP tipo magiclink y canjearlo por sesión en el servidor
    const { data: link, error: eLink } = await supabaseAdmin.auth.admin.generateLink({
      type: "magiclink",
      email,
    });
    if (eLink) return res.status(400).json({ error: eLink.message });

    // En supabase-js v2 el token_hash viene dentro de properties.email_otp.token_hash
    const token_hash =
      // @ts-ignore - defensivo por si cambia la forma
      link?.properties?.email_otp?.token_hash ||
      // @ts-ignore
      link?.email_otp?.token_hash;

    if (!token_hash) {
      return res.status(500).json({ error: "No se pudo obtener token_hash del magic link" });
    }

    // Canjear token_hash -> crear sesión
    const anon = supabaseServer();
    const { data: verified, error: eVerify } = await anon.auth.verifyOtp({
      email,
      token_hash,
      type: "magiclink",
    });
    if (eVerify || !verified?.session) {
      return res.status(400).json({ error: eVerify?.message || "No se pudo crear la sesión" });
    }

    // 4) Opcional: persistir refresh token en cookie si el usuario quiere "Recordarme"
    if (verified.session.refresh_token) {
      setRefreshCookie(res, verified.session.refresh_token, Boolean(recordarme));
    }

    return res.status(200).json({
      usuarioId: verified.user?.id,
      email: verified.user?.email,
      accessToken: verified.session.access_token,
      expiresIn: verified.session.expires_in,
      tokenType: verified.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
