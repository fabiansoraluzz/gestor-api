// api/auth/me.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

type UserLite = { id: string; email: string | null; user_metadata?: any };

function splitFullName(full: string | undefined) {
  const s = (full ?? "").trim();
  if (!s) return { nombres: null as string | null, apellidos: null as string | null };
  const parts = s.split(/\s+/);
  if (parts.length === 1) return { nombres: parts[0], apellidos: null };
  if (parts.length === 2) return { nombres: parts[0], apellidos: parts[1] };
  return {
    nombres: parts.slice(0, -2).join(" "),
    apellidos: parts.slice(-2).join(" "),
  };
}

function usernameBaseFrom(user: UserLite) {
  const meta = user.user_metadata ?? {};
  const mUser: string | undefined =
    (meta.username as string | undefined) ||
    (user.email ? user.email.split("@")[0] : undefined);
  return (mUser ?? `user-${user.id.slice(0, 8)}`).toLowerCase().replace(/[^a-z0-9._-]/g, "");
}

async function ensureUniqueUsername(base: string): Promise<string> {
  const clean = base || "user";
  let tryName = clean.slice(0, 32);
  for (let i = 0; i < 120; i++) {
    // ¿existe?
    const { data } = await supabaseAdmin
      .from("tblPerfiles")
      .select("id")
      .eq("usuario", tryName)
      .maybeSingle();
    if (!data) return tryName;

    // siguiente intento
    if (i < 99) {
      const suffix = `-${String(i + 1).padStart(2, "0")}`;
      tryName = (clean + suffix).slice(0, 32);
    } else {
      const rand = Math.random().toString(36).slice(2, 8);
      tryName = `${clean.slice(0, 32 - 7)}-${rand}`;
    }
  }
  return `${clean}-${Date.now()}`.slice(0, 32);
}

async function adoptOrCreateProfile(user: UserLite) {
  const email = user.email?.toLowerCase() ?? null;

  // 1) ¿ya existe por auth_usuario_id?
  const byAuth = await supabaseAdmin
    .from("tblPerfiles")
    .select("*")
    .eq("auth_usuario_id", user.id)
    .maybeSingle();
  if (byAuth.data) return byAuth.data;

  // 2) Adoptar por correo (si existe fila con ese correo)
  if (email) {
    const byMail = await supabaseAdmin
      .from("tblPerfiles")
      .select("*")
      .eq("correo", email)
      .maybeSingle();

    if (byMail.data) {
      const upd = await supabaseAdmin
        .from("tblPerfiles")
        .update({ auth_usuario_id: user.id })
        .eq("id", byMail.data.id)
        .select("*")
        .single();
      if (!upd.error) return upd.data;
    }
  }

  // 3) Crear nuevo perfil con username único
  const base = usernameBaseFrom(user);
  const usuario = await ensureUniqueUsername(base);
  const { nombres, apellidos } = splitFullName(user.user_metadata?.full_name);

  // Nota: si 'correo' es UNIQUE y ya está en otra fila, el insert fallará.
  //       Ya intentamos adoptarla arriba; si hubo carrera, reintentamos leer por auth_usuario_id.
  const ins = await supabaseAdmin
    .from("tblPerfiles")
    .insert({
      auth_usuario_id: user.id,
      usuario,
      correo: email,
      nombres,
      apellidos,
      activo: true,
    })
    .select("*")
    .single();

  if (!ins.error) return ins.data;

  // Reintento: si hubo carrera por correo/usuario, ya debería existir por auth_usuario_id
  const byAuth2 = await supabaseAdmin
    .from("tblPerfiles")
    .select("*")
    .eq("auth_usuario_id", user.id)
    .maybeSingle();
  if (byAuth2.data) return byAuth2.data;

  throw ins.error;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");

  const auth = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!auth) return err(res, 401, "AUTH.NO_TOKEN", "Falta token de acceso");

  const supa = supabaseServer(auth);
  const { data: uData, error: uErr } = await supa.auth.getUser();
  if (uErr || !uData?.user) return err(res, 401, "AUTH.INVALID_TOKEN", "Token inválido");

  const user: UserLite = {
    id: uData.user.id,
    email: uData.user.email ?? null,
    user_metadata: uData.user.user_metadata ?? {},
  };

  try {
    const perfil = await adoptOrCreateProfile(user);

    // roles
    const { data: roles } = await supabaseAdmin
      .from("tblRoles_Usuarios")
      .select("tblRoles(clave)")
      .eq("perfil_id", perfil.id);

    const rolesArr =
      roles?.map((r: any) => r.tblRoles?.clave).filter(Boolean) ?? [];

    return ok(res, 200, "AUTH.ME_OK", "Perfil obtenido", {
      ...perfil,
      roles: rolesArr,
    });
  } catch (e: any) {
    return err(res, 500, "DB.UNEXPECTED", "No se pudo obtener/crear el perfil", e?.message);
  }
}
