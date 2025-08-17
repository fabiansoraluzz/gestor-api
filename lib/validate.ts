// api/lib/validate.ts
import { z } from "zod";

// Campos base
const email = z.string().email("Correo inválido");
const password = z.string().min(6, "La contraseña debe tener mínimo 6 caracteres");

// ===== Auth: Login =====
// Soporta 2 variantes: con contraseña (actual) y con patrón (pendiente de activar).
export const loginSchema = z.union([
  z.object({
    email,
    password,
    recordarme: z.boolean().optional(),
  }),
  z.object({
    email,
    pattern: z.string().min(4, "Patrón inválido"),
    recordarme: z.boolean().optional(),
  }),
]);
export type LoginInput = z.infer<typeof loginSchema>;

// ===== Auth: Register =====
export const registerSchema = z.object({
  nombreCompleto: z.string().min(2, "Ingresa tu nombre completo"),
  email,
  password,
  // Dejar opcional por ahora; cuando activemos patrón en registro, lo usaremos.
  pattern: z.string().min(4, "Patrón inválido").optional(),
});
export type RegisterInput = z.infer<typeof registerSchema>;

// ===== Auth: Forgot password =====
export const forgotSchema = z.object({
  email,
  redirectTo: z.string().url().optional(),
});

// ===== Auth: Reset password (si usas flujo de reset con token) =====
export const resetPasswordSchema = z.object({
  accessToken: z.string().min(1, "Token inválido"),
  password,
  pattern: z.string().min(4, "Patrón inválido").optional(),
});

// ===== Patrón (endpoints futuros) =====
export const setPatternSchema = z.object({
  email,
  pattern: z.string().min(4, "Patrón inválido"),
});

export const patternLoginSchema = z.object({
  email,
  pattern: z.string().min(4, "Patrón inválido"),
  recordarme: z.boolean().optional(),
});
