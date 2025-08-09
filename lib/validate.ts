import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  recordarme: z.boolean().default(false),
});

export const registerSchema = z.object({
  nombreCompleto: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
});

export const forgotSchema = z.object({
  email: z.string().email(),
  redirectTo: z.string().url().optional(),
});
