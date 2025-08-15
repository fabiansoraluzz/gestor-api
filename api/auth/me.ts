// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { supabaseServer } from "../../lib/supabase";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).end();

  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Sin token" });

  const token = auth.slice("Bearer ".length);
  const supabase = supabaseServer();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return res.status(401).json({ error: "Token inválido" });

  const nombre =
    (data.user.user_metadata?.full_name as string | undefined) ??
    (data.user.user_metadata?.name as string | undefined) ??
    (data.user.email?.split("@")[0]) ??
    "Usuario";

  return res.status(200).json({ usuarioId: data.user.id, email: data.user.email, nombre });
}
