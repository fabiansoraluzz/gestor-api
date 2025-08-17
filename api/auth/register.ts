// api/auth/register.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { registerSchema } from "../../lib/validate";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { hashPattern } from "../../lib/pattern"; // 👈 ajustado

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = (req.headers["content-type"] || "").toString();
  if (!ct.includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { nombreCompleto, email, password, pattern } = registerSchema.parse(body);

    // 1) Registrar usuario
    const supa = supabaseServer();
    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: { data: { full_name: nombreCompleto } },
    });
    if (error) return res.status(400).json({ error: error.message });

    const user = data.user || null;
    const requiereConfirmacion = !data.session;

    // 2) Si llegó patrón, guardamos su hash (con service-role para saltar RLS)
    if (pattern && user) {
      const { salt, hash } = hashPattern(pattern); // 👈 aquí ya tenemos ambos
      const { error: pErr } = await supabaseAdmin
        .from("auth_patterns")
        .upsert({ user_id: user.id, email, salt, hash }, { onConflict: "user_id" });
      if (pErr) return res.status(400).json({ error: `No se pudo guardar el patrón: ${pErr.message}` });
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
