// /api/producto/nuevo.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin } from "../../lib/supabase";
import { ok, err, extractMessage } from "../../lib/http";
import { z } from "zod";

/**
 * POST /producto/nuevo
 * Llama al SP fn_producto_crear (SKU autogenerado + validaciones + auditoría)
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
 *   strNotas?: string | null
 * }
 * NOTA: NO se acepta SKU en el body (lo genera el SP)
 */
const schema = z.object({
  intCategoriaId: z.number().int().positive(),
  intUnidadId: z.number().int().positive(),
  strMedida: z.string().trim().min(1),
  strNombre: z.string().trim().min(1),
  uuidPerfilId: z
    .string()
    .uuid({ message: "uuidPerfilId inválido (uuid requerido)" }),
  intMarcaId: z.number().int().positive().nullable().optional(),
  strColor: z.string().trim().min(1).nullable().optional(),
  strVariante: z.string().trim().min(1).nullable().optional(),
  strCodigoBarras: z.string().trim().min(1).nullable().optional(),
  strNotas: z.string().trim().min(1).nullable().optional(),
});

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;

  if (req.method !== "POST") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  const ct = String(req.headers["content-type"] || "");
  if (!ct.includes("application/json")) {
    return err(
      res,
      415,
      "VALIDATION.UNSUPPORTED_CONTENT_TYPE",
      "Content-Type debe ser application/json"
    );
  }

  try {
    const raw =
      typeof req.body === "string" ? JSON.parse(req.body) : (req.body ?? {});
    const v = schema.parse(raw);

    // PROTECCIÓN: no permitir que el front intente colar SKU
    if ("strSKU" in raw) {
      return err(
        res,
        400,
        "PRODUCT.SKU_NOT_ALLOWED",
        "No envíes SKU; se autogenera en el servidor"
      );
    }

    const { data, error } = await supabaseAdmin.rpc("fn_producto_crear", {
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
    });

    if (error) {
      // Mapeo de errores comunes desde el SP
      const msg = String(error.message || error.name || "Error creando producto");

      // Violación de unique lógico (firma o SKU)
      if (/duplicate key value/i.test(msg) || error.code === "23505") {
        return err(
          res,
          409,
          "PRODUCT.DUPLICATE",
          "Ya existe un producto con la misma combinación (categoría, unidad, marca, medida, color) o el SKU se encuentra en uso",
          msg
        );
      }

      // FKs
      if (error.code === "23503") {
        return err(res, 400, "PRODUCT.FK_INVALID", "Categoría/Unidad/Marca inválida", msg);
      }

      // Validaciones del SP (22023)
      if (error.code === "22023") {
        return err(res, 400, "PRODUCT.VALIDATION", extractMessage(error) || msg);
      }

      return err(res, 400, "PRODUCT.CREATE_FAILED", "No se pudo crear el producto", msg);
    }

    if (!data) {
      return err(res, 500, "PRODUCT.NO_DATA", "El procedimiento no devolvió datos");
    }

    return ok(res, 201, "PRODUCT.CREATED", "Producto creado con éxito", data);
  } catch (e: any) {
    return err(res, 400, "VALIDATION.BAD_REQUEST", extractMessage(e));
  }
}
