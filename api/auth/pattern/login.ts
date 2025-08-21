// api/auth/pattern/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../../lib/supabase";
import { patternLoginSchema } from "../../../lib/validate";
import { setRefreshCookie } from "../../../lib/cookies";

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
    const { identifier, pattern, recordarme } = patternLoginSchema.parse(raw);

    // 1) Verificar patrón (RPC acepta email o phone)
    const { data: profileId, error: eRpc } = await supabaseAdmin
      .rpc("verify_pattern_by_identifier", { p_identifier: identifier, p_plain: pattern });

    if (eRpc || !profileId) {
      return res.status(401).json({ error: "Patrón no configurado o inválido" });
    }

    // 2) Resolver email y auth_user_id según el tipo de identificador
    const { data: prof, error: eProf } = await supabaseAdmin
      .from("profiles")
      .select("email, auth_user_id")
      .eq(isPhone(identifier) ? "phone" : "email", identifier)
      .maybeSingle();

    if (eProf || !prof?.email || !prof?.auth_user_id) {
      return res.status(400).json({ error: "No se pudo resolver el usuario" });
    }

    // 3) Generar magic link (un solo uso) y canjear por sesión
    const { data: link, error: eLink } = await supabaseAdmin.auth.admin.generateLink({
      type: "magiclink",
      email: prof.email,
    });
    if (eLink) return res.status(500).json({ error: eLink.message });

    const token_hash = link?.properties?.hashed_token as string | undefined;
    if (!token_hash) return res.status(500).json({ error: "No se pudo obtener token_hash del magic link" });

    const supa = supabaseServer();
    const { data: verify, error: eVerify } = await supa.auth.verifyOtp({
      type: "email",
      token_hash,
    });
    if (eVerify || !verify?.user || !verify?.session) {
      return res.status(401).json({ error: eVerify?.message ?? "No se pudo canjear el token" });
    }

    // 4) Cookie refresh
    if (verify.session.refresh_token) {
      setRefreshCookie(res, verify.session.refresh_token, Boolean(recordarme));
    }

    // 5) Respuesta estándar
    return res.status(200).json({
      usuarioId: verify.user.id,
      email: verify.user.email,
      nombre:
        (verify.user.user_metadata?.full_name as string | undefined) ??
        (verify.user.user_metadata?.name as string | undefined) ??
        verify.user.email?.split("@")[0] ??
        "Usuario",
      accessToken: verify.session.access_token,
      expiresIn: verify.session.expires_in,
      tokenType: verify.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
