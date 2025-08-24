import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer } from "../../lib/supabase";
import { resetPasswordSchema } from "../../lib/validate";
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
    const { accessToken, refreshToken, password } = resetPasswordSchema.parse(raw);

    // 1) Crear cliente sin sesión
    const supa = supabaseServer();

    // 2) Establecer sesión con los tokens del enlace de recuperación
    const setRes = await supa.auth.setSession({ access_token: accessToken, refresh_token: refreshToken });
    if (setRes.error || !setRes.data?.session) {
      return err(res, 401, "AUTH.SESSION_SET_FAILED", "No se pudo establecer la sesión de recuperación", setRes.error?.message);
    }

    // 3) Actualizar contraseña
    const { data, error } = await supa.auth.updateUser({ password });
    if (error) {
      return err(res, 400, "AUTH.RESET_FAILED", "No se pudo actualizar la contraseña", error.message);
    }

    return ok(res, 200, "AUTH.RESET_OK", "Contraseña actualizada", { userId: data.user?.id });
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
