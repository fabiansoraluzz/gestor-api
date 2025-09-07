// api/inventario/resumen.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

/**
 * GET /api/inventario/resumen
 * - Lee métricas de inventario: categorías activas, productos activos,
 *   “top vendidos” (productos con egresos en la ventana) y low-stock.
 * - Ventana de tiempo opcional con query params: ?desde=ISO&hasta=ISO
 *   Si se omite, la función usa últimos 7 días por defecto.
 *
 * Requiere en BD:
 *   - public.fn_inventario_resumen(p_desde timestamptz default null, p_hasta timestamptz default null)
 *   - (Opcional) public.vwInventarioResumen como fallback sin parámetros
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  try {
    // --- Lee query params (opcionales) ---
    const desdeRaw = Array.isArray(req.query.desde) ? req.query.desde[0] : req.query.desde;
    const hastaRaw = Array.isArray(req.query.hasta) ? req.query.hasta[0] : req.query.hasta;

    // Valida que sean fechas ISO válidas (suaves: si no son válidas, no se envían)
    const isValidISO = (v?: string) => {
      if (!v) return false;
      const t = Date.parse(v);
      return Number.isFinite(t);
    };

    const args: { p_desde?: string; p_hasta?: string } = {};
    if (isValidISO(desdeRaw)) args.p_desde = new Date(desdeRaw as string).toISOString();
    if (isValidISO(hastaRaw)) args.p_hasta = new Date(hastaRaw as string).toISOString();

    // --- Llama al RPC; si no existe, cae a la vista ---
    // Nota: fn_inventario_resumen devuelve 1 fila (TABLE), por eso .single()
    let { data, error } = await supabaseAdmin.rpc("fn_inventario_resumen", args).single();

    // Fallback si la función no existiera por algún motivo
    if (error && /fn_inventario_resumen/i.test(error.message)) {
      const alt = await supabaseAdmin.from("vwInventarioResumen").select("*").single();
      data = alt.data as any;
      error = alt.error as any;
    }

    if (error) {
      return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo obtener el resumen", error.message);
    }

    // data esperado:
    // {
    //   dtmDesde: string, dtmHasta: string,
    //   intCategorias: number, intProductos: number,
    //   intTopVendidos: number, intLowStocks: number
    // }
    return ok(res, 200, "INVENTORY.SUMMARY_OK", "Resumen obtenido", data);
  } catch (e: any) {
    const msg = e?.message ?? "Error procesando la solicitud";
    return err(res, 500, "INVENTORY.SUMMARY_ERROR", "No se pudo obtener el resumen", msg);
  }
}
