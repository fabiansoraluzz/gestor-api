// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") return res.status(405).end();

  const auth = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!auth) return res.status(401).json({ error: "Sin token" });

  try {
    const supa = supabaseServer();
    const { data, error } = await supa.auth.getUser(auth);
    if (error || !data?.user) return res.status(401).json({ error: "Token inválido" });

    // Buscar perfil para exponer username / nombres (best-effort)
    const { data: perfil } = await supabaseAdmin
      .from("perfiles")
      .select("usuario,nombres,apellidos")
      .eq("auth_usuario_id", data.user.id)
      .maybeSingle();

    return res.status(200).json({
      usuarioId: data.user.id,
      email: data.user.email,
      usuario: perfil?.usuario ?? data.user.user_metadata?.username ?? null,
      nombres: perfil?.nombres ?? null,
      apellidos: perfil?.apellidos ?? null,
    });
  } catch (e: any) {
    return res.status(400).json({ error: e?.message ?? "Error inesperado" });
  }
}
