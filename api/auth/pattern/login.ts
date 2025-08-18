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

    // 1) Tomar salt/hash del patrón con Service Role (bypassa RLS)
    const { data: pat, error: ePat } = await supabaseAdmin
      .from("auth_patterns")
      .select("user_id, salt, hash")
      .eq("email", email)
      .single();

    if (ePat || !pat) {
      return res.status(401).json({ error: "Patrón no configurado" });
    }

    // 2) Verificar patrón
    const ok = verifyPattern(pattern, pat.salt, pat.hash);
    if (!ok) return res.status(401).json({ error: "Patrón inválido" });

    // 3) Generar magic link admin y extraer el token_hash (según la versión)
    const { data: link, error: eGen } = await (supabaseAdmin as any).auth.admin.generateLink({
      type: "magiclink",
      email,
      // options: { redirectTo: process.env.MAGIC_REDIRECT ?? "https://example.com" } // opcional
    });
    if (eGen || !link) {
      return res.status(500).json({ error: eGen?.message ?? "No se pudo generar magic link" });
    }

    // Diferentes lugares posibles del token hash según la versión:
    const tokenHash =
      (link as any)?.hashed_token ??
      (link as any)?.properties?.hashed_token ??
      (link as any)?.properties?.email_otp?.hashed_token ??
      (link as any)?.email_otp?.hashed_token;

    if (!tokenHash) {
      // Para depurar, puedes loguear las keys de link (en dev), pero no devuelvas todo al cliente en prod.
      return res.status(500).json({ error: "No se pudo obtener token_hash del magic link" });
    }

    // 4) Canjear token_hash => sesión de Supabase
    const anon = supabaseServer(); // cliente público
    const { data: ses, error: eVerify } = await anon.auth.verifyOtp({
      type: "magiclink",
      email,
      token_hash: tokenHash,
    });

    if (eVerify || !ses?.session || !ses?.user) {
      return res.status(401).json({ error: eVerify?.message ?? "No se pudo iniciar sesión" });
    }

    // 5) Cookie refresh opcional (si quieres remember me)
    if (ses.session.refresh_token) {
      setRefreshCookie(res, ses.session.refresh_token, Boolean(recordarme));
    }

    const nombre =
      (ses.user.user_metadata?.full_name as string | undefined) ??
      (ses.user.user_metadata?.name as string | undefined) ??
      ses.user.email?.split("@")[0] ??
      "Usuario";

    return res.status(200).json({
      ok: true,
      usuarioId: ses.user.id,
      email: ses.user.email,
      nombre,
      accessToken: ses.session.access_token,
      expiresIn: ses.session.expires_in,
      tokenType: ses.session.token_type,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
