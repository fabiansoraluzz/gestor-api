// api/auth/register.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { registerSchema } from "../../lib/validate";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { username, email, password, nombres, apellidos } = registerSchema.parse(raw);

    const supa = supabaseServer();
    const full_name = [nombres ?? "", apellidos ?? ""].join(" ").trim();

    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: { data: { username, full_name } },
    });

    if (error) {
      const msg = String(error.message || error.name || "Error registrando");
      // Mapeo útil
      if (/User already registered/i.test(msg)) return res.status(409).json({ error: "Correo ya registrado" });
      if (/Database error saving new user/i.test(msg)) return res.status(400).json({ error: "Error en BD al crear usuario (revisa constraints/triggers)" });
      return res.status(400).json({ error: msg });
    }

    // Best-effort: completar nombres/apellidos en perfiles (service role; RLS no aplica)
    if (data.user) {
      await supabaseAdmin
        .from("perfiles")
        .update({ nombres, apellidos, usuario: username, correo: email })
        .eq("auth_usuario_id", data.user.id);
    }

    // Si la confirmación de email está activada no habrá session:
    const requiresConfirmation = !data.session;

    return res.status(200).json({
      usuarioId: data.user?.id,
      email: data.user?.email ?? email,
      requiereConfirmacion: requiresConfirmation,
      accessToken: data.session?.access_token,
      expiresIn: data.session?.expires_in,
      tokenType: data.session?.token_type,
    });
  } catch (e: any) {
    const msg = e?.issues ?? e?.message ?? "Solicitud inválida";
    return res.status(400).json({ error: msg });
  }
}
