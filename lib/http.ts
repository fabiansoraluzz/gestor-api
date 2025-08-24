import type { VercelResponse } from "@vercel/node";

export type ApiResponse<T = unknown> = {
  status: "success" | "error";
  code: string;
  message: string;
  data: T[];
};

export function ok<T>(
  res: VercelResponse,
  httpStatus: number,
  code: string,
  message: string,
  data?: T | T[] | null
) {
  const arr = Array.isArray(data) ? data : data != null ? [data] : [];
  const payload: ApiResponse<T> = { status: "success", code, message, data: arr };
  return res.status(httpStatus).json(payload);
}

export function err(
  res: VercelResponse,
  httpStatus: number,
  code: string,
  message: string,
  extra?: unknown
) {
  const arr = extra != null ? [extra] : [];
  const payload: ApiResponse = { status: "error", code, message, data: arr };
  return res.status(httpStatus).json(payload);
}

// Utilidad para mensajes de Zod u otros errores
export function extractMessage(e: any): string {
  if (e?.issues && Array.isArray(e.issues)) {
    return e.issues.map((i: any) => i?.message).filter(Boolean).join("; ");
  }
  return e?.message ?? String(e);
}
