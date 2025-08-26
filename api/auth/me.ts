// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

type MinimalUser = { id: string; email?: string | null; user_metadata?: any };

async function ensurePerfil(user: MinimalUser) {
  const { data: existente } = await supabaseAdmin
    .from("tblPerfiles")
    .select("id")
    .eq("auth_usuario_id", user.id)
    .maybeSingle();
  if (existente?.id) return existente.id;

  const base = (user.user_metadata?.username ??
    user.email?.split?.("@")?.[0] ??
    "user")
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "")
    .slice(0, 32) || "user";

  let usuario = base.length >= 3 ? base : "user";
  for (let i = 0; i < 5; i++) {
    const { data: dup } = await supabaseAdmin.from("tblPerfiles").select("id").eq("usuario", usuario).maybeSingle();
    if (!dup?.id) break;
    usuario = `${base}-${String(i + 1).padStart(2, "0")}`.slice(0, 32);
  }

  const { data: ins, error: insErr } = await supabaseAdmin
    .from("tblPerfiles")
    .insert({ auth_usuario_id: user.id, usuario, correo: user.email?.toLowerCase() ?? null, activo: true })
    .select("id")
    .single();

  if (insErr?.code === "23505") {
    const { data: again } = await supabaseAdmin
      .from("tblPerfiles")
      .select("id")
      .eq("auth_usuario_id", user.id)
      .maybeSingle();
    if (again?.id) return again.id;
  }

  const perfilId = ins?.id ?? null;
  if (perfilId) {
    const { data: rol } = await supabaseAdmin.from("tblRoles").select("id").eq("clave", "Empleado").single();
    if (rol?.id) await supabaseAdmin.from("tblRoles_Usuarios").insert({ perfil_id: perfilId, rol_id: rol.id });
  }
  return perfilId;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");

  const auth = req.headers.authorization || "";
  const m = auth.match(/^Bearer (.+)$/i);
  if (!m) return err(res, 401, "AUTH.UNAUTHORIZED", "Falta token de autorización");
  const accessToken = m[1];

  const supa = supabaseServer(accessToken);
  const { data: userData, error: userErr } = await supa.auth.getUser();
  if (userErr || !userData?.user) {
    return err(res, 401, "AUTH.UNAUTHORIZED", "Token inválido o expirado", userErr?.message);
  }
  const u = userData.user;

  await ensurePerfil({ id: u.id, email: u.email ?? null, user_metadata: u.user_metadata });

  const { data: perfil, error: pErr } = await supabaseAdmin
    .from("tblPerfiles")
    .select(
      "id, auth_usuario_id, usuario, correo, nombres, apellidos, avatar_url, activo, creado_en, actualizado_en"
    )
    .eq("auth_usuario_id", u.id)
    .maybeSingle();

  if (pErr) return err(res, 500, "DB.QUERY_FAILED", "Error consultando perfil", pErr.message);
  if (!perfil) return err(res, 404, "DB.PERFIL_NOT_FOUND", "No se encontró el perfil");

  const { data: ru, error: rErr } = await supabaseAdmin
    .from("tblRoles_Usuarios")
    .select("rol_id")
    .eq("perfil_id", perfil.id);
  if (rErr) return err(res, 500, "DB.QUERY_FAILED", "Error consultando roles", rErr.message);

  let roles: string[] = [];
  if (ru?.length) {
    const ids = ru.map((x) => x.rol_id);
    const { data: rows, error: nErr } = await supabaseAdmin.from("tblRoles").select("clave").in("id", ids);
    if (nErr) return err(res, 500, "DB.QUERY_FAILED", "Error consultando nombres de roles", nErr.message);
    roles = (rows ?? []).map((r) => r.clave);
  }

  return ok(res, 200, "AUTH.ME_OK", "Perfil obtenido", { ...perfil, roles });
}
