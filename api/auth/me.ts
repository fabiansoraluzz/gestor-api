// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

/** Sanea username básico para fallback */
function sanitizeUsername(s: string) {
  const base = (s || "").toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (base.length < 3) return `user-${Math.random().toString(36).slice(2, 8)}`;
  return base.slice(0, 32);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) {
    return err(res, 401, "AUTH.MISSING_TOKEN", "Falta token");
  }

  const supa = supabaseServer(token);
  const { data: userData, error: userErr } = await supa.auth.getUser();
  if (userErr || !userData?.user) {
    return err(res, 401, "AUTH.INVALID_TOKEN", "Token inválido o expirado");
  }

  const user = userData.user; // supabase-js: email es string | undefined
  const email = user.email ?? null;

  // 1) Intentar obtener perfil
  const { data: perfil, error: pfErr } = await supabaseAdmin
    .from("tblPerfiles")
    .select(
      "id, auth_usuario_id, usuario, correo, nombres, apellidos, avatar_url, activo, creado_en, actualizado_en"
    )
    .eq("auth_usuario_id", user.id)
    .maybeSingle();

  let perfilRow = perfil;

  // 2) Autocurar si no existe
  if (!perfilRow) {
    const usernameBase =
      (user.user_metadata as any)?.username ||
      (email ? email.split("@")[0] : "") ||
      `user-${user.id.slice(0, 8)}`;

    const { data: ins, error: insErr } = await supabaseAdmin
      .from("tblPerfiles")
      .insert({
        auth_usuario_id: user.id,
        usuario: sanitizeUsername(usernameBase),
        correo: email?.toLowerCase() ?? null,
        nombres: null,
        apellidos: null,
        activo: true,
      })
      .select(
        "id, auth_usuario_id, usuario, correo, nombres, apellidos, avatar_url, activo, creado_en, actualizado_en"
      )
      .single();

    if (insErr || !ins) {
      return err(
        res,
        404,
        "DB.PERFIL_NOT_FOUND",
        "No se encontró el perfil",
        insErr?.message
      );
    }
    perfilRow = ins;
  }

  // 3) Cargar roles (si falla, devolvemos [] y listo)
  let roles: string[] = [];
  try {
    const { data: rws } = await supabaseAdmin
      .from("tblRoles_Usuarios")
      .select("tblRoles (clave)")
      .eq("perfil_id", perfilRow.id);

    roles =
      (rws ?? [])
        .map((r: any) => r?.tblRoles?.clave)
        .filter(Boolean) ?? [];
  } catch {
    roles = [];
  }

  return ok(res, 200, "AUTH.ME_OK", "Perfil cargado", {
    ...perfilRow,
    roles,
  });
}
