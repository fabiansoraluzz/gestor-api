// api/auth/pattern/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../../lib/supabase";
import { patternLoginSchema } from "../../../lib/validate";
import { verifyPattern } from "../../../lib/pattern";
import { setRefreshCookie } from "../../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, pattern, recordarme } = patternLoginSchema.parse(raw);

    // 1) Buscar salt+hash del patrón
    const anon = supabaseServer();
    const { data: patRow, error: patErr } = await anon
      .from("auth_patterns")
      .select("user_id, email, salt, hash")
      .eq("email", email)
      .maybeSingle(); // puede ser null si no existe

    if (patErr) return res.status(400).json({ error: patErr.message });
    if (!patRow) return res.status(401).json({ error: "Patrón no configurado" });

    // 2) Verificar patrón
    const ok = verifyPattern(pattern, patRow.salt, patRow.hash);
    if (!ok) return res.status(401).json({ error: "Patrón inválido" });

    // 3) Generar magic link (server-side) y extraer token_hash
    const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
      email,
      type: "magiclink",
    });
    if (linkErr) return res.status(400).json({ error: linkErr.message });

    const actionLink = linkData?.properties?.action_link;
    if (!actionLink) return res.status(400).json({ error: "No se pudo generar magic link" });

    const token_hash = new URL(actionLink).searchParams.get("token_hash");
    if (!token_hash) return res.status(400).json({ error: "token_hash ausente" });

    // 4) Canjear token_hash por sesión
    const { data: verify, error: verErr } = await anon.auth.verifyOtp({
      type: "magiclink",
      token_hash,
    });
    if (verErr || !verify?.session || !verify?.user) {
      return res.status(401).json({ error: verErr?.message ?? "No se pudo iniciar sesión" });
    }

    // 5) "Recordarme" → guardar refresh_token en cookie
    if (verify.session.refresh_token) {
      setRefreshCookie(res, verify.session.refresh_token, Boolean(recordarme));
    }

    // 6) Responder como el login normal
    const nombre =
      (verify.user.user_metadata?.full_name as string | undefined) ??
      (verify.user.user_metadata?.name as string | undefined) ??
      (verify.user.email?.split("@")[0]) ??
      "Usuario";

    return res.status(200).json({
      usuarioId: verify.user.id,
      email: verify.user.email,
      nombre,
      accessToken: verify.session.access_token,
      expiresIn: verify.session.expires_in,
      tokenType: verify.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
