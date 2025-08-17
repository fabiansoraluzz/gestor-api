// api/auth/reset-password.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { resetPasswordSchema } from "../../lib/validate";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { hashPattern } from "../../lib/pattern";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { accessToken, password, pattern } = resetPasswordSchema.parse(raw);

    // Actualiza password con el accessToken del enlace de reset
    const url = `${process.env.SUPABASE_URL}/auth/v1/user`;
    const r = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`,
        "apikey": process.env.SUPABASE_ANON_KEY || "",
      },
      body: JSON.stringify({ password })
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      return res.status(400).json({ error: t || "No se pudo actualizar la contraseña" });
    }

    const updated = await r.json();
    const userId: string | undefined = updated?.id;
    const email:  string | undefined = updated?.email;

    if (pattern && userId && email) {
      const { salt, hash } = hashPattern(pattern);
      const { error } = await supabaseAdmin.from("auth_patterns").upsert({
        user_id: userId, email, salt, hash
      });
      if (error) return res.status(400).json({ error: "Contraseña cambiada pero falló el patrón: " + error.message });
    }

    return res.status(204).end();
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
