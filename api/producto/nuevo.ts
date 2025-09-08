// /api/producto/nuevo.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin } from "../../lib/supabase";
import { ok, err, extractMessage } from "../../lib/http";
import { z } from "zod";

/**
 * POST /producto/nuevo
 * Crea un producto o suma stock si ya existe la misma configuración.
 * (SKU autogenerado + validaciones + auditoría + movimiento ingreso opcional)
 *
 * Body esperado (JSON):
 * {
 *   intCategoriaId: number,
 *   intUnidadId: number,
 *   strMedida: string,
 *   strNombre: string,        // lo arma el front (auto)
 *   uuidPerfilId: string,     // auditoría (uuid de tblPerfiles)
 *   intMarcaId?: number | null,
 *   strColor?: string | null,
 *   strVariante?: string | null,
 *   strCodigoBarras?: string | null,
 *   strNotas?: string | null,
 *   decCantidad?: number,     // opcional: >0 para ingresar stock
 *   intAlmacenId?: number     // requerido si envías decCantidad
 * }
 * NOTA: NO aceptar SKU en el body (lo genera el SP).
 */
const schema = z.object({
  intCategoriaId: z.number().int().positive(),
  intUnidadId: z.number().int().positive(),
  strMedida: z.string().trim().min(1),
  strNombre: z.string().trim().min(1),
  uuidPerfilId: z.string().uuid({ message: "uuidPerfilId inválido (uuid requerido)" }),
  intMarcaId: z.number().int().positive().nullable().optional(),
  strColor: z.string().trim().min(1).nullable().optional(),
  strVariante: z.string().trim().min(1).nullable().optional(),
  strCodigoBarras: z.string().trim().min(1).nullable().optional(),
  strNotas: z.string().trim().min(1).nullable().optional(),
  decCantidad: z.number().nonnegative().optional(),
  intAlmacenId: z.number().int().positive().optional(),
}).refine(
  (v) => (v.decCantidad === undefined || v.decCantidad === null) || (v.intAlmacenId !== undefined && v.intAlmacenId !== null),
  { message: "intAlmacenId es requerido cuando envías decCantidad", path: ["intAlmacenId"] }
);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;

  if (req.method !== "POST") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  const ct = String(req.headers["content-type"] || "");
  if (!ct.includes("application/json")) {
    return err(res, 415, "VALIDATION.UNSUPPORTED_CONTENT_TYPE", "Content-Type debe ser application/json");
  }

  try {
    const raw = typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const v = schema.parse(raw);

    // Protección: no permitir SKU desde el front
    if ("strSKU" in raw) {
      return err(res, 400, "PRODUCT.SKU_NOT_ALLOWED", "No envíes SKU; se autogenera en el servidor");
    }

    // Llamada al SP "crear o sumar"
    const { data, error } = await supabaseAdmin.rpc("fn_producto_crear_o_sumar", {
      p_intcategoriaid: v.intCategoriaId,
      p_intunidadid: v.intUnidadId,
      p_strmedida: v.strMedida,
      p_strnombre: v.strNombre,
      p_uuidperfilid: v.uuidPerfilId,
      p_intmarcaid: v.intMarcaId ?? null,
      p_strcolor: v.strColor ?? null,
      p_strvariante: v.strVariante ?? null,
      p_strcodigobarras: v.strCodigoBarras ?? null,
      p_strnotas: v.strNotas ?? null,
      p_deccantidad: v.decCantidad ?? 0,
      p_intalmacenid: v.intAlmacenId ?? null,
    });

    if (error) {
      const msg = String(error.message || error.name || "Error creando/sumando producto");

      if (/duplicate key value/i.test(msg) || error.code === "23505") {
        return err(
          res,
          409,
          "PRODUCT.DUPLICATE",
          "Conflicto de duplicidad al crear el producto",
          msg
        );
      }

      if (error.code === "23503") {
        return err(res, 400, "PRODUCT.FK_INVALID", "Categoría/Unidad/Marca/Almacén inválida", msg);
      }

      if (error.code === "22023") {
        return err(res, 400, "PRODUCT.VALIDATION", extractMessage(error) || msg);
      }

      return err(res, 400, "PRODUCT.CREATE_FAILED", "No se pudo procesar el producto", msg);
    }

    if (!data) {
      return err(res, 500, "PRODUCT.NO_DATA", "El procedimiento no devolvió datos");
    }

    // data es el JSONB retornado por el SP
    const payload = data as {
      accion: "CREAR" | "SUMAR";
      producto: any;
      cantidadAgregada: number;
      unidad: string;
      mensaje: string;
    };

    // Mensaje y status según acción
    if (payload.accion === "SUMAR") {
      // << Requisito: mapear un mensaje cuando se suma al existente >>
      return ok(res, 200, "PRODUCT.STOCK_SUMMED", payload.mensaje, payload);
    } else {
      return ok(res, 201, "PRODUCT.CREATED", payload.mensaje || "Producto creado con éxito", payload);
    }
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
