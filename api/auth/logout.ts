// api/auth/logout.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { cors } from "../../lib/cors";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).end();

  return res.status(204).end();
}
