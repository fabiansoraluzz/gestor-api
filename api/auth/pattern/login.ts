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

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, pattern, recordarme } = patternLoginSchema.parse(raw);

    // 1) Buscar salt/hash del patrón por email
    const { data: row, error: eRow } = await supabaseAdmin
      .from("auth_patterns")
      .select("user_id, email, salt, hash")
      .eq("email", email)
      .single();

    if (eRow || !row) return res.status(401).json({ error: "Patrón no configurado" });

    // 2) Verificar patrón
    const ok = verifyPattern(pattern, row.salt, row.hash);
    if (!ok) return res.status(401).json({ error: "Patrón inválido" });

    // 3) Generar magic link y obtener hashed_token
    const { data: link, error: eLink } = await supabaseAdmin.auth.admin.generateLink({
      type: "magiclink",
      email,
    });
    if (eLink) return res.status(500).json({ error: eLink.message });

    const token_hash = link?.properties?.hashed_token as string | undefined;
    if (!token_hash) {
      return res.status(500).json({ error: "No se pudo obtener token_hash del magic link" });
    }

    // 4) Canjear token_hash POR SESIÓN (OJO: SOLO token_hash y type)
    const supa = supabaseServer();
    const { data: v, error: eVerify } = await supa.auth.verifyOtp({
      type: "email", // 'email' es el tipo correcto para magic link
      token_hash,
    });

    if (eVerify || !v?.user || !v?.session) {
      return res.status(401).json({ error: eVerify?.message ?? "No se pudo canjear el token" });
    }

    // 5) Cookie de refresh si aplica
    if (v.session.refresh_token) {
      setRefreshCookie(res, v.session.refresh_token, Boolean(recordarme));
    }

    // 6) Respuesta estándar como /auth/login
    return res.status(200).json({
      usuarioId: v.user.id,
      email: v.user.email,
      nombre:
        (v.user.user_metadata?.full_name as string | undefined) ??
        (v.user.user_metadata?.name as string | undefined) ??
        v.user.email?.split("@")[0] ??
        "Usuario",
      accessToken: v.session.access_token,
      expiresIn: v.session.expires_in,
      tokenType: v.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
