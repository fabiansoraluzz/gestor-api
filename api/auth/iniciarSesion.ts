// api/auth/iniciarSesion.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { z } from "zod";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { ok, err, extractMessage } from "../../lib/http";
import { setRefreshCookie, clearRefreshCookie } from "../../lib/cookies";

const loginSchema = z.union([
  z.object({ email: z.string().email(), password: z.string().min(6), remember: z.boolean().optional() }),
  z.object({
    username: z.string().min(3).max(32).regex(/^[a-z0-9._-]+$/),
    password: z.string().min(6),
    remember: z.boolean().optional(),
  }),
]);

function getCookie(req: VercelRequest, name: string): string | null {
  const c = req.headers.cookie || "";
  const m = c.split(";").map((s) => s.trim()).find((p) => p.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : null;
}

function sanitizeBase(u: string | null | undefined) {
  const base = (u ?? "").toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32);
  return base.length >= 3 ? base : "user";
}

// ⚠️ Tipo permite email undefined | null
type MinimalUser = { id: string; email?: string | null; user_metadata?: any };

async function ensurePerfil(user: MinimalUser) {
  const { data: existente } = await supabaseAdmin
    .from("tblPerfiles")
    .select("id")
    .eq("auth_usuario_id", user.id)
    .maybeSingle();
  if (existente?.id) return existente.id;

  const meta = user.user_metadata ?? {};
  const base = sanitizeBase(meta.username ?? (user.email?.split?.("@")?.[0] ?? "user"));
  let candidato = base;

  for (let i = 0; i < 7; i++) {
    const { data: dup } = await supabaseAdmin
      .from("tblPerfiles")
      .select("id")
      .eq("usuario", candidato)
      .maybeSingle();
    if (!dup?.id) break;
    candidato =
      i < 5
        ? `${base}-${String(i + 1).padStart(2, "0")}`.slice(0, 32)
        : `${base}-${Math.random().toString(36).slice(2, 6)}`.slice(0, 32);
  }

  const { data: ins, error: insErr } = await supabaseAdmin
    .from("tblPerfiles")
    .insert({
      auth_usuario_id: user.id,
      usuario: candidato,
      correo: user.email?.toLowerCase() ?? null,
      activo: true,
    })
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

  try {
    if (req.method === "GET") {
      const rt = getCookie(req, "sb-refresh");
      if (!rt) return err(res, 401, "AUTH.NO_REFRESH_COOKIE", "No hay cookie de sesión");

      const supa = supabaseServer();
      const { data, error } = await supa.auth.refreshSession({ refresh_token: rt });
      if (error || !data?.session || !data.user) {
        clearRefreshCookie(res);
        return err(res, 401, "AUTH.REFRESH_FAILED", "No se pudo refrescar la sesión", error?.message);
      }

      await ensurePerfil({ id: data.user.id, email: data.user.email ?? null, user_metadata: data.user.user_metadata });

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

    const ct = req.headers["content-type"] || "";
    if (!ct.toString().includes("application/json")) {
      return err(res, 415, "VALIDATION.UNSUPPORTED_CONTENT_TYPE", "Content-Type debe ser application/json");
    }

    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const parsed = loginSchema.parse(raw);
    const remember = "remember" in parsed ? !!parsed.remember : false;

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
      const extras = /Email not confirmed/i.test(error?.message || "") ? "Email not confirmed" : undefined;
      return err(res, 401, "AUTH.INVALID_CREDENTIALS", "Usuario o contraseña inválidos", extras);
    }

    await ensurePerfil({ id: data.user.id, email: data.user.email ?? null, user_metadata: data.user.user_metadata });

    if (remember && data.session.refresh_token) setRefreshCookie(res, data.session.refresh_token, true);
    else clearRefreshCookie(res);

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
