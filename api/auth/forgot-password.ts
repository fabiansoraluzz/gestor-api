import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer } from "../../lib/supabase";
import { forgotSchema } from "../../lib/validate";

const DEFAULT_REDIRECT = process.env.PASSWORD_RESET_REDIRECT || "http://localhost:5173/auth/reset";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return; 
  if (req.method !== "POST") return res.status(405).end();

  const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
  try {
    const { email, redirectTo } = forgotSchema.parse(body);
    const supabase = supabaseServer();

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: redirectTo || DEFAULT_REDIRECT
    });
    if (error) return res.status(400).json({ error: error.message });
    return res.status(204).end();
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
