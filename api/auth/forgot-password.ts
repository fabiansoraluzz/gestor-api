// api/auth/forgot-password.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { forgotSchema } from "../../lib/validate";
import { supabaseServer } from "../../lib/supabase";

const DEFAULT_REDIRECT =
  process.env.PASSWORD_RESET_REDIRECT ||
  process.env.NEXT_PUBLIC_PASSWORD_RESET_REDIRECT ||
  undefined;

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, redirectTo } = forgotSchema.parse(raw);

    const supa = supabaseServer();
    const { error } = await supa.auth.resetPasswordForEmail(email, {
      redirectTo: redirectTo || DEFAULT_REDIRECT,
    });
    if (error) return res.status(400).json({ error: error.message });

    return res.status(204).end();
  } catch (e: any) {
    return res.status(400).json({ error: e?.issues ?? e?.message ?? "Solicitud inválida" });
  }
}
