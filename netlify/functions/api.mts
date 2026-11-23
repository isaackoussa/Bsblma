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

  // ---------- Routes publiques (site vitrine) ----------
  if (route === "public") {
    const [, what, pid] = parts;
    // Tarifs + photos choisies par LMA (aucune donnée cliente n'est renvoyée).
    if (what === "catalog" && req.method === "GET") {
      const data = (await s.get("data", { type: "json" })) as any;
      const styles = Array.isArray(data?.siteStyles)
        ? data.siteStyles.map((x: any) => ({ n: String(x.n ?? ""), p: Number(x.p) || 0 })).filter((x: any) => x.n)
        : null;
      const photos = Array.isArray(data?.photos)
        ? data.photos.filter((x: any) => x && x.site && x.synced !== false).map((x: any) => ({ id: String(x.id), style: String(x.prestation ?? "") }))
        : [];
      return new Response(JSON.stringify({ styles, photos }), {
        headers: { "content-type": "application/json", "cache-control": "public, max-age=60" },
      });
    }
    // Une photo publiée sur le site, servie comme image.
    if (what === "photo" && pid && /^[a-z0-9]{4,32}$/i.test(pid) && req.method === "GET") {
      const data = (await s.get("data", { type: "json" })) as any;
      const ok = Array.isArray(data?.photos) && data.photos.some((x: any) => x && x.id === pid && x.site);
      if (!ok) return json({ error: "not_found" }, 404);
      const src = await s.get(`photos/${pid}`);
      const m = src && /^data:(image\/[a-z+.-]+);base64,(.+)$/i.exec(src);
      if (!m) return json({ error: "not_found" }, 404);
      return new Response(Buffer.from(m[2], "base64"), {
        headers: { "content-type": m[1], "cache-control": "public, max-age=3600" },
      });
    }
    // Demande de rendez-vous envoyée depuis le site.
    if (what === "booking" && req.method === "POST") {
      const text = await req.text();
      if (text.length > 4000) return json({ error: "too_large" }, 413);
      let b: Record<string, unknown>;
      try { b = JSON.parse(text); } catch { return json({ error: "bad_json" }, 400); }
      const str = (k: string, max = 160) => String(b?.[k] ?? "").trim().slice(0, max);
      const booking = {
        name: str("name", 60), phone: str("phone", 30), style: str("style", 60), length: str("length", 30),
        hairByLma: !!b?.hairByLma, hair: str("hair", 30), sens: str("sens", 160),
        commune: str("commune", 40), place: str("place", 120), mark: str("mark", 160),
        date: /^\d{4}-\d{2}-\d{2}$/.test(str("date", 10)) ? str("date", 10) : "",
        slot: str("slot", 20), low: Number(b?.low) || 0, high: Number(b?.high) || 0,
        createdAt: Date.now(),
      };
      if (!booking.name || !booking.phone || !booking.place) return json({ error: "missing_fields" }, 400);
      const { blobs } = await s.list({ prefix: "requests/" });
      if (blobs.length >= 300) return json({ error: "too_many" }, 429);
      const rid = Date.now().toString(36) + randomBytes(4).toString("hex");
      await s.setJSON(`requests/${rid}`, { id: rid, ...booking });
      return json({ ok: true });
    }
    return json({ error: "not_found" }, 404);
  }

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

  // Demandes reçues du site : l'app les importe puis les efface du serveur.
  if (route === "requests") {
    if (req.method === "GET" && !id) {
      const { blobs } = await s.list({ prefix: "requests/" });
      const list = [];
      for (const b of blobs.slice(0, 100)) {
        const r = await s.get(b.key, { type: "json" });
        if (r) list.push(r);
      }
      return json({ requests: list });
    }
    if (req.method === "DELETE" && id && /^[a-z0-9]{4,40}$/i.test(id)) {
      await s.delete(`requests/${id}`);
      return json({ ok: true });
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
