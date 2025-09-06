// /api/inventario/productos.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

/**
 * GET /inventario/productos
 * Listado desde la vista vwInventarioProductos
 * Parámetros de query (todos opcionales):
 *  - q: string (busca por nombre o SKU, ILIKE)
 *  - categoriaId: number
 *  - unidadId: number
 *  - marcaId: number
 *  - stockBajo: boolean ("true"/"false")
 *  - activo: boolean ("true"/"false")
 *  - sort: "actualizado_en" | "strNombre" | "strSKU" | "numStockActual"
 *  - order: "asc" | "desc"
 *  - limit: number, offset: number  (no devolvemos meta; solo filas)
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;

  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  try {
    const q = String(req.query.q ?? "").trim();
    const categoriaId = Number(req.query.categoriaId ?? 0) || null;
    const unidadId = Number(req.query.unidadId ?? 0) || null;
    const marcaId = Number(req.query.marcaId ?? 0) || null;
    const stockBajo =
      typeof req.query.stockBajo === "string"
        ? req.query.stockBajo === "true"
        : null;
    const activo =
      typeof req.query.activo === "string"
        ? req.query.activo === "true"
        : null;

    const sort = (String(req.query.sort ?? "actualizado_en") ||
      "actualizado_en") as
      | "actualizado_en"
      | "strNombre"
      | "strSKU"
      | "numStockActual";
    const order = (String(req.query.order ?? "desc") || "desc") as
      | "asc"
      | "desc";

    const limit = Math.max(0, Math.min(Number(req.query.limit ?? 25), 500));
    const offset = Math.max(0, Number(req.query.offset ?? 0));

    const supa = supabaseAdmin;

    let query = supa.from("vwInventarioProductos").select("*");

    // búsqueda
    if (q) {
      // strNombre ILIKE %q% OR strSKU ILIKE %q%
      query = query.or(
        `strNombre.ilike.%${q}%,strSKU.ilike.%${q}%`
      );
    }

    // filtros exactos
    if (categoriaId) query = query.eq("intCategoriaId", categoriaId);
    if (unidadId) query = query.eq("intUnidadId", unidadId);
    if (marcaId) query = query.eq("intMarcaId", marcaId);
    if (stockBajo !== null) query = query.eq("boolStockBajo", stockBajo);
    if (activo !== null) query = query.eq("boolActivo", activo);

    // orden
    const allowedSort = new Set([
      "actualizado_en",
      "strNombre",
      "strSKU",
      "numStockActual",
    ]);
    const sortCol = allowedSort.has(sort) ? sort : "actualizado_en";
    query = query.order(sortCol, { ascending: order === "asc" });

    // paginación simple (sin meta)
    if (limit > 0) {
      const rangeFrom = offset;
      const rangeTo = offset + limit - 1;
      query = query.range(rangeFrom, rangeTo);
    }

    const { data, error } = await query;

    if (error) {
      return err(res, 400, "INVENTORY.LIST_FAILED", "No se pudo obtener el inventario", error.message);
    }

    // entregamos SOLO filas (sin meta)
    return ok(res, 200, "INVENTORY.LIST_OK", "Listado obtenido", data ?? []);
  } catch (e: any) {
    return err(res, 500, "INVENTORY.UNEXPECTED", "Error inesperado", String(e?.message ?? e));
  }
}
