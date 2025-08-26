// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  // 1) validar bearer
  const auth = req.headers.authorization || "";
  const m = auth.match(/^Bearer (.+)$/i);
  if (!m) return err(res, 401, "AUTH.UNAUTHORIZED", "Falta token de autorización");
  const accessToken = m[1];

  // 2) obtener user desde el token
  const supa = supabaseServer(accessToken);
  const { data: userData, error: userErr } = await supa.auth.getUser();
  if (userErr || !userData?.user) {
    return err(res, 401, "AUTH.UNAUTHORIZED", "Token inválido o expirado", userErr?.message);
  }
  const userId = userData.user.id;

  // 3) perfil (consulta directa, sin agregados)
  const { data: perfil, error: pErr } = await supabaseAdmin
    .from("tblPerfiles")
    .select(
      "id, auth_usuario_id, usuario, correo, nombres, apellidos, avatar_url, activo, creado_en, actualizado_en"
    )
    .eq("auth_usuario_id", userId)
    .maybeSingle();

  if (pErr) {
    return err(res, 500, "DB.QUERY_FAILED", "Error consultando perfil", pErr.message);
  }
  if (!perfil) {
    return err(res, 404, "DB.PERFIL_NOT_FOUND", "No se encontró el perfil");
  }

  // 4) roles (segunda consulta simple)
  const { data: ru, error: rErr } = await supabaseAdmin
    .from("tblRoles_Usuarios")
    .select("rol_id")
    .eq("perfil_id", perfil.id);

  if (rErr) {
    return err(res, 500, "DB.QUERY_FAILED", "Error consultando roles", rErr.message);
  }

  let roles: string[] = [];
  if (ru && ru.length) {
    const ids = ru.map((x) => x.rol_id);
    const { data: rows, error: nErr } = await supabaseAdmin
      .from("tblRoles")
      .select("clave")
      .in("id", ids);

    if (nErr) {
      return err(res, 500, "DB.QUERY_FAILED", "Error consultando nombres de roles", nErr.message);
    }
    roles = (rows ?? []).map((r) => r.clave);
  }

  // 5) respuesta normalizada (ApiEnvelope)
  return ok(res, 200, "AUTH.ME_OK", "Perfil obtenido", {
    ...perfil,
    roles,
  });
}
