// api/auth/reset-password.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { resetPasswordSchema } from "../../lib/validate";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { accessToken, password } = resetPasswordSchema.parse(raw);

    // Identificar usuario a partir del access_token del link de recuperación
    const supa = supabaseServer();
    const { data: u, error: eUser } = await supa.auth.getUser(accessToken);
    if (eUser || !u?.user) return res.status(400).json({ error: eUser?.message ?? "Token inválido" });

    // Actualizar contraseña con service role
    const { error: eUpd } = await supabaseAdmin.auth.admin.updateUserById(u.user.id, {
      password,
    });
    if (eUpd) return res.status(400).json({ error: eUpd.message });

    return res.status(200).json({ ok: true });
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
