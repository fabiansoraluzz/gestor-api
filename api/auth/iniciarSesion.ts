// api/auth/iniciarSesion.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { z } from "zod";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err, extractMessage } from "../../lib/http";
import { setRefreshCookie, clearRefreshCookie } from "../../lib/cookies";

// schema de login local (acepta email O username) + remember opcional
const loginSchema = z.union([
  z.object({ email: z.string().email(), password: z.string().min(6), remember: z.boolean().optional() }),
  z.object({
    username: z
      .string()
      .min(3)
      .max(32)
      .regex(/^[a-z0-9._-]+$/),
    password: z.string().min(6),
    remember: z.boolean().optional(),
  }),
]);

// lee cookie simple
function getCookie(req: VercelRequest, name: string): string | null {
  const c = req.headers.cookie || "";
  const m = c.split(";").map((s) => s.trim()).find((p) => p.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;

  try {
    if (req.method === "GET") {
      // 🔹 Rehidratar sesión desde refresh cookie (sb-refresh)
      const rt = getCookie(req, "sb-refresh");
      if (!rt) {
        return err(res, 401, "AUTH.NO_REFRESH_COOKIE", "No hay cookie de sesión");
      }

      const supa = supabaseServer();
      const { data, error } = await supa.auth.refreshSession({ refresh_token: rt });

      if (error || !data?.session || !data.user) {
        // borra cookie inválida
        clearRefreshCookie(res);
        return err(res, 401, "AUTH.REFRESH_FAILED", "No se pudo refrescar la sesión", error?.message);
      }

      // renueva cookie de refresh 30 días
      setRefreshCookie(res, data.session.refresh_token!, true);

      return ok(res, 200, "AUTH.REFRESH_OK", "Sesión rehidratada", {
        usuarioId: data.user.id,
        email: data.user.email ?? null,
        usuario: (data.user.user_metadata?.username as string | undefined) ?? null,
        nombre:
          (data.user.user_metadata?.full_name as string | undefined) ??
          data.user.email?.split("@")[0] ??
          null,
        accessToken: data.session.access_token,
        refreshToken: data.session.refresh_token,
        expiresIn: data.session.expires_in,
        tokenType: data.session.token_type,
      });
    }

    if (req.method !== "POST") {
      return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
    }

    // 🔹 Login normal (POST)
    const ct = req.headers["content-type"] || "";
    if (!ct.toString().includes("application/json")) {
      return err(
        res,
        415,
        "VALIDATION.UNSUPPORTED_CONTENT_TYPE",
        "Content-Type debe ser application/json"
      );
    }

    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const parsed = loginSchema.parse(raw);
    const remember = "remember" in parsed ? !!parsed.remember : false;

    // si vino username, resolve a email desde DB
    let emailToUse: string | null = null;
    if ("email" in parsed) {
      emailToUse = parsed.email.toLowerCase();
    } else {
      const { data: row, error: qErr } = await supabaseAdmin
        .from("tblPerfiles")
        .select("correo")
        .eq("usuario", parsed.username.toLowerCase())
        .maybeSingle();
      if (qErr) return err(res, 500, "DB.QUERY_FAILED", "Error consultando usuario", qErr.message);
      if (!row?.correo) return err(res, 401, "AUTH.INVALID_CREDENTIALS", "Usuario o contraseña inválidos");
      emailToUse = row.correo as string;
    }

    const supa = supabaseServer();
    const { data, error } = await supa.auth.signInWithPassword({
      email: emailToUse!,
      password: parsed.password,
    });

    if (error || !data?.session || !data?.user) {
      // indicación de email no confirmado
      const msg = error?.message || "";
      const extras = /Email not confirmed/i.test(msg) ? "Email not confirmed" : undefined;
      return err(
        res,
        401,
        "AUTH.INVALID_CREDENTIALS",
        extras ? "Usuario o contraseña inválidos" : "Usuario o contraseña inválidos",
        extras
      );
    }

    // setear/limpiar refresh cookie según "remember"
    if (remember && data.session.refresh_token) {
      setRefreshCookie(res, data.session.refresh_token, true); // 30 días
    } else {
      clearRefreshCookie(res);
    }

    return ok(res, 200, "AUTH.LOGIN_OK", "Inicio de sesión correcto", {
      usuarioId: data.user.id,
      email: data.user.email ?? null,
      usuario: (data.user.user_metadata?.username as string | undefined) ?? null,
      nombre:
        (data.user.user_metadata?.full_name as string | undefined) ??
        data.user.email?.split("@")[0] ??
        null,
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresIn: data.session.expires_in,
      tokenType: data.session.token_type,
      remember,
    });
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
