// api/lib/cookies.ts
import type { VercelResponse } from "@vercel/node";

const COOKIE_NAME = "sb-refresh";

// ✅ Para enviar cookies en requests cross-site (localhost → vercel.app)
// necesitas SameSite=None + Secure
export function setRefreshCookie(res: VercelResponse, token: string, remember: boolean) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",               // << antes estaba Lax
  ];
  if (remember) parts.push(`Max-Age=${60 * 60 * 24 * 30}`); // 30 días
  res.setHeader("Set-Cookie", parts.join("; "));
}

export function clearRefreshCookie(res: VercelResponse) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`
  );
}
