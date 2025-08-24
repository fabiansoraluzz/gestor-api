import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { loginSchema } from "../../lib/validate";
import { setRefreshCookie } from "../../lib/cookies";
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
    const parsed = loginSchema.parse(raw);

    const remember =
      typeof raw.remember === "boolean"
        ? raw.remember
        : typeof raw.recordar === "boolean"
        ? raw.recordar
        : false;

    // Resolver email si vino username
    let email: string | null = null;
    if ("email" in parsed) {
      email = parsed.email;
    } else {
      const { data: row, error } = await supabaseAdmin
        .from("tblPerfiles")
        .select("correo")
        .eq("usuario", parsed.username.toLowerCase())
        .maybeSingle();

      if (error) {
        return err(res, 500, "DB.SELECT_FAILED", "No se pudo resolver el correo por usuario", error.message);
      }
      if (!row?.correo) {
        return err(res, 401, "AUTH.INVALID_CREDENTIALS", "Usuario o contraseña inválidos");
      }
      email = row.correo as string;
    }

    const supa = supabaseServer();
    const { data, error } = await supa.auth.signInWithPassword({
      email: email!,
      password: parsed.password,
    });

    if (error || !data?.session || !data?.user) {
      return err(res, 401, "AUTH.INVALID_CREDENTIALS", "Usuario o contraseña inválidos", error?.message);
    }

    if (data.session.refresh_token && remember) {
      setRefreshCookie(res, data.session.refresh_token, true);
    }

    const { data: perfil, error: perErr } = await supabaseAdmin
      .from("tblPerfiles")
      .select("id,usuario,nombres,apellidos")
      .eq("auth_usuario_id", data.user.id)
      .maybeSingle();

    if (perErr) {
      // No es crítico para iniciar sesión; devolvemos sesión aunque falle el perfil
      return ok(res, 200, "AUTH.LOGIN_OK_WITHOUT_PROFILE", "Sesión iniciada (perfil no disponible)", {
        usuarioId: data.user.id,
        email: data.user.email,
        usuario: data.user.user_metadata?.username,
        nombre: data.user.email?.split("@")[0] ?? "Usuario",
        accessToken: data.session.access_token,
        refreshToken: data.session.refresh_token,
        expiresIn: data.session.expires_in,
        tokenType: data.session.token_type,
        remember,
      });
    }

    const nombre = `${perfil?.nombres ?? ""} ${perfil?.apellidos ?? ""}`.trim();
    return ok(res, 200, "AUTH.LOGIN_OK", "Sesión iniciada", {
      usuarioId: data.user.id,
      email: data.user.email,
      usuario: perfil?.usuario ?? data.user.user_metadata?.username,
      nombre: nombre || data.user.email?.split("@")[0] || "Usuario",
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
