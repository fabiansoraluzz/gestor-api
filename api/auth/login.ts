// api/auth/login.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin, supabaseServer } from "../../lib/supabase";
import { loginSchema } from "../../lib/validate";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  const ct = req.headers["content-type"] || "";
  if (!ct.toString().includes("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const parsed = loginSchema.parse(raw);

    // Resolver a email si vino username
    let email: string | null = null;
    if ("email" in parsed) {
      email = parsed.email;
    } else {
      // Buscar correo por username en la tabla 'perfiles' (RLS requiere service role)
      const { data: row, error } = await supabaseAdmin
        .from("perfiles")
        .select("correo")
        .eq("usuario", parsed.username)
        .maybeSingle();

      if (error) return res.status(500).json({ error: error.message });
      if (!row?.correo) return res.status(401).json({ error: "Usuario o contraseña inválidos" });
      email = row.correo as string;
    }

    const supa = supabaseServer();
    const { data, error } = await supa.auth.signInWithPassword({
      email: email!,
      password: parsed.password,
    });

    if (error || !data?.session || !data?.user) {
      return res.status(401).json({ error: "Usuario o contraseña inválidos" });
    }

    // Enriquecer con username/nombres desde perfiles (best-effort)
    let nombre: string | undefined = undefined;
    let usuario: string | undefined = undefined;

    const { data: perfil } = await supabaseAdmin
      .from("perfiles")
      .select("usuario,nombres,apellidos")
      .eq("auth_usuario_id", data.user.id)
      .maybeSingle();

    if (perfil) {
      usuario = perfil.usuario ?? undefined;
      const nombres = perfil.nombres ?? "";
      const apellidos = perfil.apellidos ?? "";
      const full = `${nombres} ${apellidos}`.trim();
      nombre = full || usuario || (data.user.email?.split("@")[0] ?? "Usuario");
    } else {
      nombre =
        (data.user.user_metadata?.username as string | undefined) ??
        data.user.email?.split("@")[0] ??
        "Usuario";
    }

    return res.status(200).json({
      usuarioId: data.user.id,
      email: data.user.email,
      usuario,
      nombre,
      accessToken: data.session.access_token,
      expiresIn: data.session.expires_in,
      tokenType: data.session.token_type, // "bearer"
    });
  } catch (e: any) {
    const msg = e?.issues ?? e?.message ?? "Solicitud inválida";
    return res.status(400).json({ error: msg });
  }
}
