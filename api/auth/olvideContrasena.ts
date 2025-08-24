import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer } from "../../lib/supabase";
import { forgotSchema } from "../../lib/validate";
import { ok, err, extractMessage } from "../../lib/http";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return err(res, 415, "VALIDATION.UNSUPPORTED_CONTENT_TYPE", "Content-Type debe ser application/json");
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { email, redirectTo } = forgotSchema.parse(raw);
    const redirect = redirectTo || process.env.PASSWORD_RESET_REDIRECT || "";

    const supa = supabaseServer();
    // Por seguridad, no revelamos si el correo existe. Siempre devolvemos success.
    await supa.auth.resetPasswordForEmail(email, { redirectTo: redirect });

    return ok(res, 200, "AUTH.RECOVERY_EMAIL_SENT", "Si el correo existe, se envió un enlace de recuperación.");
  } catch (e: any) {
    // Si realmente quieres ver la causa exacta, descomenta para no enmascarar:
    // return err(res, 400, "AUTH.RECOVERY_FAILED", extractMessage(e));
    // Mantengo mejor práctica:
    return ok(res, 200, "AUTH.RECOVERY_EMAIL_SENT", "Si el correo existe, se envió un enlace de recuperación.");
  }
}
