// api/lib/validate.ts
import { z } from "zod";

// Reglas base
export const email = z.string().trim().email("Correo inválido");
export const password = z
  .string()
  .min(6, "La contraseña debe tener mínimo 6 caracteres");

export const username = z
  .string()
  .trim()
  .min(3, "El usuario debe tener al menos 3 caracteres")
  .max(32, "Máximo 32 caracteres")
  .regex(/^[a-z0-9._-]+$/, "Solo minúsculas, números, punto, guion y guion bajo")
  .transform((s) => s.toLowerCase());

// ===== Auth: Login =====
// Acepta { email, password } O { username, password }
export const loginSchema = z.union([
  z.object({
    email,
    password,
  }),
  z.object({
    username,
    password,
  }),
]);
export type LoginInput = z.infer<typeof loginSchema>;

// ===== Auth: Register =====
// (En API exigimos email, aunque en DB sea opcional)
export const registerSchema = z.object({
  username,
  email,
  password,
  nombres: z.string().trim().min(1, "Ingresa tus nombres").optional(),
  apellidos: z.string().trim().min(1, "Ingresa tus apellidos").optional(),
});
export type RegisterInput = z.infer<typeof registerSchema>;

// ===== Auth: Forgot password =====
export const forgotSchema = z.object({
  email,
  redirectTo: z.string().url().optional(),
});

// ===== Auth: Reset password =====
export const resetPasswordSchema = z.object({
  accessToken: z.string().min(1, "Token inválido"),
  password,
});
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
