// api/auth/register.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { registerSchema } from "../../lib/validate";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = (req.headers["content-type"] || "").toString();
  if (!ct.includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { username, email, password, nombres, apellidos } = registerSchema.parse(body);

    // Pre-chequeo de disponibilidad de username (usa service role por RLS)
    const { data: exists, error: e1 } = await supabaseAdmin
      .from("perfiles")
      .select("id")
      .eq("usuario", username)
      .maybeSingle();

    if (e1) return res.status(500).json({ error: e1.message });
    if (exists) return res.status(409).json({ error: "El nombre de usuario ya está en uso" });

    const full_name = [nombres, apellidos].filter(Boolean).join(" ").trim();

    const supa = supabaseServer();
    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: {
        data: {
          username, // nuestro trigger lo tomará
          nombres,
          apellidos,
          full_name, // compat
        },
      },
    });

    if (error) return res.status(400).json({ error: error.message });

    const user = data.user || null;
    const requiereConfirmacion = !data.session;

    return res.status(201).json({
      usuarioId: user?.id ?? null,
      email,
      usuario: username,
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
