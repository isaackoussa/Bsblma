// Sauvegarde en ligne de Braids Style by LMA.
// Les données (rendez-vous, caisse, stock, infos des photos) et chaque photo
// sont stockées dans Netlify Blobs. Tout est protégé par un code d'accès
// choisi par la propriétaire à la première activation (stocké haché, jamais en clair).
import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const store = () => getStore({ name: "lma", consistency: "strong" });
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { "cache-control": "no-store" } });
const MAX_PHOTO = 3_000_000; // ~3 Mo par photo (déjà compressée côté app)
const MAX_DATA = 4_000_000;

type Auth = { salt: string; hash: string };
const hashCode = (code: string, salt: string) => scryptSync(code, salt, 32).toString("hex");

async function checkCode(req: Request): Promise<Response | null> {
  const code = req.headers.get("x-lma-code") ?? "";
  const auth = (await store().get("auth", { type: "json" })) as Auth | null;
  if (!auth) return json({ error: "not_setup" }, 404);
  const a = Buffer.from(hashCode(code, auth.salt), "hex");
  const b = Buffer.from(auth.hash, "hex");
  if (!code || a.length !== b.length || !timingSafeEqual(a, b)) return json({ error: "bad_code" }, 401);
  return null;
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const [route, id] = parts;
  const s = store();

  // État : la sauvegarde a-t-elle déjà été activée ?
  if (route === "status" && req.method === "GET") {
    const auth = await s.get("auth", { type: "json" });
    return json({ setup: !!auth });
  }

  // Première activation : choisit le code d'accès (une seule fois).
  if (route === "setup" && req.method === "POST") {
    const { code } = (await req.json().catch(() => ({}))) as { code?: string };
    if (!code || code.length < 6) return json({ error: "code_too_short" }, 400);
    const salt = randomBytes(16).toString("hex");
    const { modified } = await s.setJSON("auth", { salt, hash: hashCode(code, salt) }, { onlyIfNew: true });
    if (!modified) return json({ error: "already_setup" }, 409);
    return json({ ok: true });
  }

  const denied = await checkCode(req);
  if (denied) return denied;

  if (route === "login") return json({ ok: true });

  if (route === "data") {
    if (req.method === "GET") {
      const data = await s.get("data", { type: "json" });
      return json({ data: data ?? null });
    }
    if (req.method === "PUT") {
      const text = await req.text();
      if (text.length > MAX_DATA) return json({ error: "too_large" }, 413);
      let data: { updatedAt?: number };
      try { data = JSON.parse(text); } catch { return json({ error: "bad_json" }, 400); }
      if (!data || typeof data !== "object") return json({ error: "bad_json" }, 400);
      await s.set("data", text);
      // Copie de secours du jour (une par jour, gardée).
      const day = new Date().toISOString().slice(0, 10);
      context.waitUntil(s.set(`backups/${day}`, text));
      return json({ ok: true, updatedAt: data.updatedAt ?? null });
    }
  }

  if (route === "photo" && id && /^[a-z0-9]{4,32}$/i.test(id)) {
    const key = `photos/${id}`;
    if (req.method === "GET") {
      const src = await s.get(key);
      return src === null ? json({ error: "not_found" }, 404) : json({ src });
    }
    if (req.method === "PUT") {
      const src = await req.text();
      if (!src.startsWith("data:image/")) return json({ error: "bad_image" }, 400);
      if (src.length > MAX_PHOTO) return json({ error: "too_large" }, 413);
      await s.set(key, src);
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await s.delete(key);
      return json({ ok: true });
    }
  }

  return json({ error: "not_found" }, 404);
};

export const config: Config = {
  path: "/api/*",
  rateLimit: { windowLimit: 120, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
