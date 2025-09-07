// api/inventario/resumen.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { supabaseAdmin } from "../../lib/supabase";
import { ok, err } from "../../lib/http";

/**
 * GET /api/inventario/resumen
 *
 * Responde con:
 * {
 *   "categorias": { "totalActivas": number },
 *   "productos":  { "totalActivos": number },
 *   "masMovidos": {
 *     "skus": number,                // # productos con EGRESO en el período
 *     "cantidadEgresada": number,    // SUM(decCantidad) de EGRESO en el período
 *     "top": [{ intProductoId, strSKU, strNombre, cantidad }] // top 5 (opcional, puede venir vacío)
 *   },
 *   "stock": {
 *     "bajo": number,      // stock > 0 y < umbralBajo
 *     "sinStock": number   // stock == 0
 *   },
 *   "rango": { "desde": ISOString, "hasta": ISOString }
 * }
 *
 * Query params opcionales:
 *   - desde: ISO (default: now - 7d)
 *   - hasta: ISO (default: now)
 *   - umbralBajo: number (default: process.env.INVENTORY_STOCK_LOW_THRESHOLD || 5)
 *
 * Notas:
 *   - Para "más movidos" se considera enmTipo = 'EGRESO' únicamente (ventas/salidas).
 *   - Stock se calcula con SUM(tblStock.decStock) por producto en todos los almacenes.
 *   - Solo se consideran productos activos (tblProductos.boolActivo = true).
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "GET") {
    return err(res, 405, "HTTP.METHOD_NOT_ALLOWED", "Método no permitido");
  }

  try {
    // --------- Lee y normaliza query params ---------
    const qd = Array.isArray(req.query.desde) ? req.query.desde[0] : req.query.desde;
    const qh = Array.isArray(req.query.hasta) ? req.query.hasta[0] : req.query.hasta;
    const qb = Array.isArray(req.query.umbralBajo) ? req.query.umbralBajo[0] : req.query.umbralBajo;

    const isISO = (v?: string) => (v ? Number.isFinite(Date.parse(v)) : false);
    const ahora = new Date();
    const defaultDesde = new Date(ahora.getTime() - 7 * 24 * 60 * 60 * 1000); // 7 días

    const desde = isISO(qd as string) ? new Date(qd as string) : defaultDesde;
    const hasta = isISO(qh as string) ? new Date(qh as string) : ahora;

    const envUmbral = Number(process.env.INVENTORY_STOCK_LOW_THRESHOLD || 5);
    const umbralBajo = Number.isFinite(Number(qb)) ? Math.max(0, Number(qb)) : envUmbral;

    const desdeISO = desde.toISOString();
    const hastaISO = hasta.toISOString();

    // --------- 1) Totales simples (categorías y productos activos) ----------
    const [{ count: categoriasActivas }, { count: productosActivos }] = await Promise.all([
      supabaseAdmin
        .from("tblCategorias")
        .select("*", { count: "exact", head: true })
        .eq("boolActivo", true),
      supabaseAdmin
        .from("tblProductos")
        .select("intProductoId", { count: "exact", head: true })
        .eq("boolActivo", true),
    ]).then(([c1, c2]) => [c1, c2]);

    if (categoriasActivas === null || productosActivos === null) {
      return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo contar categorías/productos");
    }

    // --------- 2) Más movidos (EGRESO en rango) ----------
    // Traemos movimientos de tipo EGRESO en ventana y los agregamos en memoria.
    // Si el volumen creciera mucho, movemos esto a un RPC/VIEW dedicado.
    const movRes = await supabaseAdmin
      .from("tblMovimientos")
      .select("intProductoId, decCantidad, dtmFecha, enmTipo")
      .eq("enmTipo", "EGRESO")
      .gte("dtmFecha", desdeISO)
      .lte("dtmFecha", hastaISO);

    if (movRes.error) {
      return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo leer movimientos", movRes.error.message);
    }

    type Mov = { intProductoId: number; decCantidad: number };
    const movs = (movRes.data as any[] as Mov[]) || [];

    // Agrupa por producto
    const agg = new Map<number, number>();
    let totalEgresado = 0;
    for (const m of movs) {
      const prev = agg.get(m.intProductoId) || 0;
      const qty = Number(m.decCantidad) || 0;
      agg.set(m.intProductoId, prev + qty);
      totalEgresado += qty;
    }

    const skus = agg.size;

    // Top 5 por cantidad
    const topPairs = [...agg.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    let top: Array<{ intProductoId: number; strSKU: string | null; strNombre: string; cantidad: number }> = [];
    if (topPairs.length > 0) {
      const ids = topPairs.map(([id]) => id);
      const prods = await supabaseAdmin
        .from("tblProductos")
        .select("intProductoId, strSKU, strNombre")
        .in("intProductoId", ids);

      if (prods.error) {
        return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo leer productos top", prods.error.message);
      }

      const mapProd = new Map<number, { strSKU: string | null; strNombre: string }>();
      (prods.data || []).forEach((p: any) =>
        mapProd.set(p.intProductoId, { strSKU: p.strSKU ?? null, strNombre: p.strNombre || "" })
      );

      top = topPairs.map(([id, cantidad]) => {
        const meta = mapProd.get(id) || { strSKU: null, strNombre: "" };
        return { intProductoId: id, strSKU: meta.strSKU, strNombre: meta.strNombre, cantidad };
      });
    }

    // --------- 3) Stock bajo / sin stock ----------
    // Tomamos todos los productos activos y todos los saldos de stock, agregamos en memoria.
    const [prodsAct, stockRows] = await Promise.all([
      supabaseAdmin.from("tblProductos").select("intProductoId").eq("boolActivo", true),
      supabaseAdmin.from("tblStock").select("intProductoId, decStock"),
    ]);

    if (prodsAct.error) {
      return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo listar productos activos", prodsAct.error.message);
    }
    if (stockRows.error) {
      return err(res, 400, "INVENTORY.SUMMARY_FAILED", "No se pudo leer stock", stockRows.error.message);
    }

    const activeIds = new Set<number>((prodsAct.data || []).map((p: any) => p.intProductoId));
    const stockAgg = new Map<number, number>();
    (stockRows.data || []).forEach((s: any) => {
      const id = Number(s.intProductoId);
      stockAgg.set(id, (stockAgg.get(id) || 0) + Number(s.decStock || 0));
    });

    let sinStock = 0;
    let bajo = 0;
    for (const id of activeIds) {
      const qty = Number(stockAgg.get(id) || 0);
      if (qty <= 0) sinStock += 1;
      else if (qty < umbralBajo) bajo += 1;
    }

    // --------- 4) Respuesta en el formato solicitado ----------
    return ok(res, 200, "INVENTORY.SUMMARY_OK", "Resumen obtenido", {
      categorias: { totalActivas: categoriasActivas },
      productos: { totalActivos: productosActivos },
      masMovidos: {
        skus,
        cantidadEgresada: totalEgresado,
        top, // puede venir vacío
      },
      stock: { bajo, sinStock },
      rango: { desde: desdeISO, hasta: hastaISO },
    });
  } catch (e: any) {
    const msg = e?.message ?? "Error procesando la solicitud";
    return err(res, 500, "INVENTORY.SUMMARY_ERROR", "No se pudo obtener el resumen", msg);
  }
}
