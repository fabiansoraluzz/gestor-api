// api/lib/validate.ts
import { z } from "zod";

/* ------------------------ helpers de teléfono ------------------------ */
function normalizePhone(raw: string) {
  const s = (raw || "").trim();
  if (!s) return "";
  // quita espacios, guiones, paréntesis… deja solo dígitos y +
  const digits = s.replace(/[^\d+]/g, "");
  // heurísticas simples (ajusta a tu país si quieres)
  if (/^\d{9}$/.test(digits)) return `+51${digits}`;                 // 9 dígitos → Perú
  if (/^\d{11}$/.test(digits) && digits.startsWith("51")) return `+${digits}`;
  if (!digits.startsWith("+")) return `+${digits}`;
  return digits;
}
const email = z.string().email("Correo inválido");
const password = z.string().min(6, "La contraseña debe tener mínimo 6 caracteres");

/* ---------------------- identificador: email/phone ------------------- */
const identifier = z.string().min(3).transform((v) => v.trim());

function toIdentifier(v: string) {
  return v.includes("@") ? v.trim() : normalizePhone(v);
}

/* ----------------------------- LOGIN PW ------------------------------ */
/** Login con contraseña. Acepta {identifier,password} o {email,password} */
export const loginPasswordSchema = z
  .object({
    identifier: identifier.transform(toIdentifier),
    password,
    recordarme: z.boolean().optional(),
  })
  .or(
    z
      .object({
        email,
        password,
        recordarme: z.boolean().optional(),
      })
      .transform(({ email, ...rest }) => ({ identifier: email, ...rest }))
  );
export type LoginPasswordInput = z.infer<typeof loginPasswordSchema>;

/* ---------------------------- LOGIN patrón --------------------------- */
/** Login por patrón. Acepta {identifier,pattern} o {email,pattern} */
export const patternLoginSchema = z
  .object({
    identifier: identifier.transform(toIdentifier),
    pattern: z.string().min(3, "Patrón inválido"),
    recordarme: z.boolean().optional(),
  })
  .or(
    z
      .object({
        email,
        pattern: z.string().min(3, "Patrón inválido"),
        recordarme: z.boolean().optional(),
      })
      .transform(({ email, ...rest }) => ({ identifier: email, ...rest }))
  );
export type PatternLoginInput = z.infer<typeof patternLoginSchema>;

/* ----------------------------- REGISTER ------------------------------ */
export const registerSchema = z.object({
  nombreCompleto: z.string().min(2, "Ingresa tu nombre completo"),
  email,
  password,
  phone: z.string().optional().transform((v) => (v ? normalizePhone(v) : undefined)),
  pattern: z.string().min(3, "Patrón inválido").optional(),
});
export type RegisterInput = z.infer<typeof registerSchema>;

/* --------------------------- FORGOT / RESET -------------------------- */
export const forgotSchema = z.object({
  email,
  redirectTo: z.string().url().optional(),
});

export const resetPasswordSchema = z.object({
  accessToken: z.string().min(1, "Token inválido"),
  password,
  pattern: z.string().min(3, "Patrón inválido").optional(),
});

/* ----------------------------- Set patrón ---------------------------- */
export const setPatternSchema = z.object({
  pattern: z.string().min(3, "Patrón inválido"),
});
