import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer } from "../../lib/supabase";
import { clearRefreshCookie } from "../../lib/cookies";
import { ok, err } from "../../lib/http";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST" && req.method !== "DELETE") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : undefined;

    if (token) {
      const supa = supabaseServer(token);
      await supa.auth.signOut(); // best-effort
    }

    clearRefreshCookie(res);
    return ok(res, 200, "AUTH.LOGOUT_OK", "Sesión cerrada");
  } catch (_e) {
    clearRefreshCookie(res);
    return ok(res, 200, "AUTH.LOGOUT_OK", "Sesión cerrada");
  }
}
