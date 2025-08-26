// api/auth/iniciarSesion.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { setRefreshCookie, clearRefreshCookie } from "../../lib/cookies";
import { ok, err, extractMessage } from "../../lib/http";
import { z } from "zod";

// ===== Schemas =====
const loginSchema = z.union([
  z.object({
    email: z.string().trim().email(),
    password: z.string().min(6),
    remember: z.boolean().optional(),
  }),
  z.object({
    username: z
      .string()
      .trim()
      .min(3)
      .max(32)
      .regex(/^[a-z0-9._-]+$/),
    password: z.string().min(6),
    remember: z.boolean().optional(),
  }),
]);

// ===== Utils =====
function getCookie(req: VercelRequest, name: string) {
  const raw = req.headers.cookie || "";
  const m = raw.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : null;
}

// Firma flexible: Supabase v2 expone user.email?: string
function shapeSession(
  user: { id: string; email: string | null | undefined; user_metadata?: any },
  session: any | null
) {
  const meta = user.user_metadata || {};
  const email = user.email ?? null;
  const username: string | undefined = meta.username;
  const fullName: string | undefined = meta.full_name;
  const nombre =
    (fullName && fullName.trim()) ||
    username ||
    (email ? email.split("@")[0] : undefined) ||
    "Usuario";

  return {
    usuarioId: user.id,
    email,
    usuario: username ?? undefined,
    nombre,
    accessToken: session?.access_token ?? null,
    refreshToken: session?.refresh_token ?? null,
    expiresIn: session?.expires_in ?? null,
    tokenType: session?.token_type ?? null,
  };
}

// ===== Handler =====
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;

  // POST => login con credenciales
  if (req.method === "POST") {
    try {
      const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
      const parsed = loginSchema.parse(raw);

      // Resolver email si viene username
      let email: string | null = null;
      if ("email" in parsed) {
        email = parsed.email.toLowerCase();
      } else {
        const { data: row, error } = await supabaseAdmin
          .from("tblPerfiles")
          .select("correo")
          .eq("usuario", parsed.username.toLowerCase())
          .maybeSingle();
        if (error) {
          return err(res, 500, "DB.SELECT_FAILED", "No se pudo resolver el usuario", error.message);
        }
        if (!row?.correo) {
          return err(res, 401, "AUTH.INVALID_CREDENTIALS", "Usuario o contraseña inválidos");
        }
        email = (row.correo as string).toLowerCase();
      }

      // Login Supabase
      const supa = supabaseServer();
      const { data, error } = await supa.auth.signInWithPassword({
        email: email!,
        password: parsed.password,
      });

      if (error || !data?.user) {
        // Propagamos razón (ej. Email not confirmed) en data[]
        return err(
          res,
          401,
          "AUTH.INVALID_CREDENTIALS",
          "Usuario o contraseña inválidos",
          error?.message
        );
      }

      // Manejo de refresh cookie (para rehidratación futura)
      const remember = !!parsed?.remember;
      if (remember && data.session?.refresh_token) {
        setRefreshCookie(res, data.session.refresh_token, true);
      } else {
        // si no quiere recordar, limpiamos si existía
        clearRefreshCookie(res);
      }

      // Respuesta
      const payload = shapeSession(
        { id: data.user.id, email: data.user.email ?? null, user_metadata: data.user.user_metadata },
        data.session
      );
      return ok(res, 200, "AUTH.LOGIN_OK", "Sesión iniciada", payload);
    } catch (e: any) {
      return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
    }
  }

  // GET => rehidratación por cookie HttpOnly (refresh)
  if (req.method === "GET") {
    const refresh = getCookie(req, "sb-refresh");
    if (!refresh) {
      return err(res, 401, "AUTH.NO_REFRESH_COOKIE", "No hay cookie de sesión");
    }

    const supa = supabaseServer();
    const { data, error } = await supa.auth.refreshSession({ refresh_token: refresh });
    if (error || !data?.user) {
      return err(res, 401, "AUTH.REFRESH_FAILED", "No se pudo rehidratar sesión", error?.message);
    }

    // Rotar refresh cookie
    if (data.session?.refresh_token) {
      setRefreshCookie(res, data.session.refresh_token, true);
    }

    const payload = shapeSession(
      { id: data.user.id, email: data.user.email ?? null, user_metadata: data.user.user_metadata },
      data.session
    );
    return ok(res, 200, "AUTH.REFRESH_OK", "Sesión rehidratada", payload);
  }

  return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
}
