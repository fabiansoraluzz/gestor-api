// api/auth/register.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { registerSchema } from "../../lib/validate";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = String(req.headers["content-type"] || "");
  if (!ct.includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { nombreCompleto, email, password, phone, pattern } = registerSchema.parse(body);

    // 1) Crear usuario en Auth
    const supa = supabaseServer();
    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: nombreCompleto },
        emailRedirectTo: process.env.EMAIL_CONFIRM_REDIRECT || undefined,
      },
    });
    if (error) return res.status(400).json({ error: error.message });

    const user = data.user || null;
    const requiereConfirmacion = !data.session;

    // 2) Guardar teléfono en profiles (si se envió)
    if (phone && user) {
      await supabaseAdmin
        .from("profiles")
        .update({ phone })
        .eq("auth_user_id", user.id);
    }

    // 3) Patrón inicial opcional (admin_set_pattern necesita profile_id)
    if (pattern && user) {
      const { data: prof } = await supabaseAdmin
        .from("profiles")
        .select("id")
        .eq("auth_user_id", user.id)
        .maybeSingle();

      if (prof?.id) {
        await supabaseAdmin.rpc("admin_set_pattern", {
          p_profile: prof.id,
          p_plain: pattern,
        });
      }
    }

    return res.status(201).json({
      usuarioId: user?.id ?? null,
      email,
      requiereConfirmacion,
      accessToken: data.session?.access_token ?? null,
    });
  } catch (e: any) {
    const msg = e?.issues ?? e?.message ?? "Solicitud inválida";
    if (msg === "fetch failed") {
      return res.status(500).json({
        error:
          "No se pudo conectar con Supabase (fetch failed). Revisa SUPABASE_URL/keys en Vercel y redeploy.",
      });
    }
    return res.status(400).json({ error: msg });
  }
}
