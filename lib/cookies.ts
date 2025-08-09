import type { VercelResponse } from "@vercel/node";

const COOKIE_NAME = "sb-refresh";

export function setRefreshCookie(res: VercelResponse, token: string, remember: boolean) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ];
  if (remember) parts.push(`Max-Age=${60 * 60 * 24 * 30}`); // 30 días
  res.setHeader("Set-Cookie", parts.join("; "));
}

export function clearRefreshCookie(res: VercelResponse) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}
