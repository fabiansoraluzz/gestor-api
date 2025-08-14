import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";
import { clearRefreshCookie } from "../../lib/cookies";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return; 
  if (req.method !== "POST") return res.status(405).end();
  clearRefreshCookie(res);
  return res.status(204).end();
}
