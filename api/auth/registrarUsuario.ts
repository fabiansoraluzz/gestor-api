// api/auth/register.ts
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
    return err(
      res,
      415,
      "VALIDATION.UNSUPPORTED_CONTENT_TYPE",
      "Content-Type debe ser application/json"
    );
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const { username, email, password, nombres, apellidos } = registerSchema.parse(raw);

    const supa = supabaseServer();
    const full_name = [nombres ?? "", apellidos ?? ""].join(" ").trim();

    // 1) Crear usuario en Auth
    const { data, error } = await supa.auth.signUp({
      email,
      password,
      options: { data: { username, full_name } },
    });

    if (error) {
      const msg = String(error.message || error.name || "Error registrando");
      // Email ya existe en AUTH
      if (/User already registered/i.test(msg)) {
        return err(res, 409, "AUTH.EMAIL_IN_USE", "El correo ya está registrado", msg);
      }
      // Error genérico BD/Auth
      if (/Database error saving new user/i.test(msg)) {
        return err(res, 400, "DB.AUTH_INSERT_FAILED", "Error en BD al crear usuario", msg);
      }
      return err(res, 400, "AUTH.SIGNUP_FAILED", "No se pudo registrar", msg);
    }

    const userId = data.user?.id;
    if (!userId) {
      return err(res, 500, "AUTH.MISSING_USER_ID", "No se pudo obtener el ID del usuario");
    }

    // 2) Insertar perfil en tblPerfiles
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
      // ---- Mapeo fino de duplicados 23505 ----
      const pgCode = perfilErr.code;
      const hayDuplicado = pgCode === "23505" || /duplicate key/i.test(perfilErr.message || "");
      if (hayDuplicado) {
        const blob = `${perfilErr.message ?? ""} ${perfilErr.details ?? ""}`.toLowerCase();

        // detecta por constraint o por "Key (campo)=..."
        const dupUsername =
          /\btblperfiles[_-]?usuario[_-]?key\b/.test(blob) ||
          /key\s*\(usuario\)/i.test(blob) ||
          /usuario/.test(blob); // último recurso

        const dupEmail =
          /\btblperfiles[_-]?correo[_-]?key\b/.test(blob) ||
          /key\s*\(correo\)/i.test(blob) ||
          /correo/.test(blob);

        const dupAuth =
          /\btblperfiles[_-]?auth_usuario_id[_-]?key\b/.test(blob) ||
          /key\s*\(auth_usuario_id\)/i.test(blob) ||
          /auth_usuario_id/.test(blob);

        if (dupEmail) {
          return err(
            res,
            409,
            "DB.DUPLICATE.EMAIL",
            "El correo ya está registrado",
            perfilErr.message || perfilErr.details
          );
        }
        if (dupUsername) {
          return err(
            res,
            409,
            "DB.DUPLICATE.USERNAME",
            "Ese usuario ya está en uso",
            perfilErr.message || perfilErr.details
          );
        }
        if (dupAuth) {
          return err(
            res,
            409,
            "DB.DUPLICATE.AUTH_USER",
            "Ese usuario de autenticación ya tiene un perfil",
            perfilErr.message || perfilErr.details
          );
        }
        // Fallback para duplicados no mapeados
        return err(
          res,
          409,
          "DB.DUPLICATE",
          "Perfil duplicado",
          perfilErr.message || perfilErr.details
        );
      }

      // Otros errores de inserción
      return err(
        res,
        400,
        "DB.INSERT_FAILED",
        "No se pudo crear el perfil",
        perfilErr.message || perfilErr.details
      );
    }

    // 3) Rol por defecto "Empleado" (best-effort)
    const { data: rol, error: rolErr } = await supabaseAdmin
      .from("tblRoles")
      .select("id")
      .eq("clave", "Empleado")
      .single();

    if (!rolErr && rol?.id) {
      await supabaseAdmin
        .from("tblRoles_Usuarios")
        .insert({ perfil_id: perfilIns.id, rol_id: rol.id });
    }

    // 4) Respuesta unificada
    const requiresConfirmation = !data.session;
    return ok(
      res,
      200,
      "AUTH.REGISTER_OK",
      requiresConfirmation
        ? "Usuario registrado. Revisa tu correo para confirmar la cuenta."
        : "Usuario registrado y sesión iniciada",
      {
        usuarioId: userId,
        email: data.user?.email ?? email,
        requiereConfirmacion: requiresConfirmation,
        accessToken: data.session?.access_token,
        refreshToken: data.session?.refresh_token,
        expiresIn: data.session?.expires_in,
        tokenType: data.session?.token_type,
      }
    );
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
