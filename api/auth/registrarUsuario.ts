import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { registerSchema } from "../../lib/validate";
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
    const { username, email, password, nombres, apellidos } = registerSchema.parse(raw);

    const supa = supabaseServer();
    const full_name = [nombres ?? "", apellidos ?? ""].join(" ").trim();

    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: { data: { username, full_name } },
    });

    if (error) {
      const msg = String(error.message || error.name || "Error registrando");
      if (/User already registered/i.test(msg)) {
        return err(res, 409, "AUTH.EMAIL_IN_USE", "El correo ya está registrado", msg);
      }
      if (/Database error saving new user/i.test(msg)) {
        return err(res, 400, "DB.AUTH_INSERT_FAILED", "Error en BD al crear usuario", msg);
      }
      return err(res, 400, "AUTH.SIGNUP_FAILED", "No se pudo registrar", msg);
    }

    const userId = data.user?.id;
    if (!userId) {
      return err(res, 500, "AUTH.MISSING_USER_ID", "No se pudo obtener el ID del usuario");
    }

    // Crear perfil
    const { data: perfilIns, error: perfilErr } = await supabaseAdmin
      .from("tblPerfiles")
      .insert({
        auth_usuario_id: userId,
        usuario: username.toLowerCase(),
        correo: email.toLowerCase(),
        nombres,
        apellidos,
        activo: true,
      })
      .select("id")
      .single();

    if (perfilErr) {
      const code = perfilErr.code === "23505" || /duplicate key/i.test(perfilErr.message)
        ? "DB.DUPLICATE"
        : "DB.INSERT_FAILED";
      return err(res, 400, code, "No se pudo crear el perfil", perfilErr.message);
    }

    // Rol por defecto "Empleado"
    const { data: rol, error: rolErr } = await supabaseAdmin
      .from("tblRoles")
      .select("id")
      .eq("clave", "Empleado")
      .single();

    if (!rolErr && rol?.id) {
      await supabaseAdmin.from("tblRoles_Usuarios").insert({ perfil_id: perfilIns.id, rol_id: rol.id });
    }

    const requiresConfirmation = !data.session;

    return ok(res, 200, "AUTH.REGISTER_OK", requiresConfirmation
      ? "Usuario registrado. Revisa tu correo para confirmar la cuenta."
      : "Usuario registrado y sesión iniciada", {
      usuarioId: userId,
      email: data.user?.email ?? email,
      requiereConfirmacion: requiresConfirmation,
      accessToken: data.session?.access_token,
      refreshToken: data.session?.refresh_token,
      expiresIn: data.session?.expires_in,
      tokenType: data.session?.token_type,
    });
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
