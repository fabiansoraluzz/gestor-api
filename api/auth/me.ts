import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseServer, supabaseAdmin } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
  if (!token) return err(res, 401, "AUTH.MISSING_TOKEN", "Falta token Bearer");

  try {
    const supa = supabaseServer(token);
    const { data: userData, error: userErr } = await supa.auth.getUser();
    if (userErr || !userData?.user) return err(res, 401, "AUTH.INVALID_TOKEN", "Token inválido", userErr?.message);

    const uid = userData.user.id;

    const { data: perfil, error: perErr } = await supa
      .from("tblPerfiles")
      .select("id, auth_usuario_id, usuario, correo, nombres, apellidos, avatar_url, activo, creado_en, actualizado_en")
      .eq("auth_usuario_id", uid)
      .single();

    if (perErr) return err(res, 404, "DB.PERFIL_NOT_FOUND", "No se encontró el perfil", perErr.message);

    const { data: rolesRows, error: rolesErr } = await supabaseAdmin
      .from("tblRoles_Usuarios")
      .select("tblRoles(clave)")
      .eq("perfil_id", perfil.id);

    if (rolesErr) {
      // Devolvemos perfil sin roles, pero indicamos en data el error de roles
      return ok(res, 200, "AUTH.ME_OK_PARTIAL", "Perfil recuperado (roles no disponibles)", {
        ...perfil,
        roles: [],
      });
    }

    const roles = (rolesRows ?? [])
      .map((r: any) => r?.tblRoles?.clave)
      .filter(Boolean);

    return ok(res, 200, "AUTH.ME_OK", "Perfil actual", { ...perfil, roles });
  } catch (e: any) {
    return err(res, 400, "INTERNAL.UNEXPECTED", e?.message ?? "Error inesperado");
  }
}
