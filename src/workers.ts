export interface Env {
  DB: D1Database;
  ALLOWED_ORIGIN: string;
  ADMIN_TOKEN?: string;
  // Optional if you enabled R2 in wrangler.toml
  BACKUPS?: R2Bucket;
}

const ok = (data: unknown, origin?: string) =>
  new Response(JSON.stringify(data), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(origin ? corsHeaders(origin) : {}),
    },
  });

const bad = (status: number, msg: string, origin?: string) =>
  new Response(JSON.stringify({ error: msg }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(origin ? corsHeaders(origin) : {}),
    },
  });

const corsHeaders = (origin: string) => ({
  "Access-Control-Allow-Origin": origin,
  "Vary": "Origin",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Admin-Token",
});

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const origin = allowOrigin(req.headers.get("Origin"), env.ALLOWED_ORIGIN);

    // CORS preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: origin ? corsHeaders(origin) : {} });
    }

    // Routes
    if (url.pathname === "/" && req.method === "GET") {
      return new Response(indexHTML(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/api/submit" && req.method === "POST") {
      const ct = req.headers.get("content-type") || "";
      let body: any = {};
      if (ct.includes("application/json")) body = await req.json();
      else if (ct.includes("application/x-www-form-urlencoded")) {
        const f = await req.formData();
        f.forEach((v, k) => (body[k] = v));
      } else return bad(415, "Unsupported content-type", origin);

      // Honeypot (spam)
      if (body.website) return ok({ status: "ok" }, origin);

      const { valid, errors, data } = validate(body);
      if (!valid) return bad(400, "Validation error: " + errors.join("; "), origin);

      const info = {
        ip: req.headers.get("CF-Connecting-IP") || "",
        ua: req.headers.get("User-Agent") || "",
      };

      // Insert
      const stmt = env.DB.prepare(`
        INSERT INTO members (
          ip,user_agent,
          nev_elotag,nev_vezetek,nev_kereszt,nev_utonev,
          szuletesi_nev,szuletesi_orszag,szuletesi_telepules,szuletesi_datum,
          anya_leanykori_nev,apa_neve,foglalkozas,
          keresztelo_felekezet,helyben_keresztelt,keresztseg_helye,keresztseg_eve,
          konfirmalt,konfirmalo_felekezet,helyben_konfirmalt,konfirmacio_helye,konfirmacio_eve,
          hazas,nem_hazas_statusz,helyben_hazassag,hazassag_helye,hazassag_eve,hazastars_neve,
          irsz,varos,utca_hazszam,epulet_emelet_ajto,
          telefon,email,
          nem_zugloi_tag_helyi_egyhaz,
          consent_contact,consent_processing,
          hely,datum,alairas
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(
        info.ip, info.ua,
        data.nev_elotag, data.nev_vezetek, data.nev_kereszt, data.nev_utonev,
        data.szuletesi_nev, data.szuletesi_orszag, data.szuletesi_telepules, data.szuletesi_datum,
        data.anya_leanykori_nev, data.apa_neve, data.foglalkozas,
        data.keresztelo_felekezet, data.helyben_keresztelt, data.keresztseg_helye, data.keresztseg_eve,
        data.konfirmalt, data.konfirmalo_felekezet, data.helyben_konfirmalt, data.konfirmacio_helye, data.konfirmacio_eve,
        data.hazas, data.nem_hazas_statusz, data.helyben_hazassag, data.hazassag_helye, data.hazassag_eve, data.hazastars_neve,
        data.irsz, data.varos, data.utca_hazszam, data.epulet_emelet_ajto,
        data.telefon, data.email,
        data.nem_zugloi_tag_helyi_egyhaz,
        data.consent_contact, data.consent_processing,
        data.hely, data.datum, data.alairas
      );

      await stmt.run();
      return ok({ status: "ok" }, origin);
    }

    if (url.pathname === "/admin/export" && req.method === "GET") {
      const token = req.headers.get("X-Admin-Token") || url.searchParams.get("token") || "";
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return bad(401, "Unauthorized");

      const { results } = await env.DB.prepare(`SELECT * FROM members ORDER BY created_at DESC`).all();
      const csv = toCSV(results || []);
      return new Response(csv, {
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": `attachment; filename=members_${new Date().toISOString().slice(0,10)}.csv`,
        },
      });
    }

    return new Response("Not found", { status: 404 });
  },

  // Nightly cron: export CSV to R2 (optional)
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    if (!env.BACKUPS) return;
    const { results } = await env.DB.prepare(`SELECT * FROM members ORDER BY created_at DESC`).all();
    const csv = toCSV(results || []);
    const key = `d1_backup_${new Date().toISOString()}.csv`;
    await env.BACKUPS.put(key, new Blob([csv], { type: "text/csv" }));
  },
};

function allowOrigin(origin: string | null, allowed: string) {
  if (!origin) return null;
  try {
    return origin === allowed ? origin : null;
  } catch { return null; }
}

function required(v?: string) { return (v ?? "").trim().length > 0; }
const phoneRe = /^0[1-9](\s?\d{1,2})?(\s?\d{3})\s?\d{4}$/; // accepts 06 1 123 4567 etc.
const dateRe  = /^\d{4}-\d{2}-\d{2}$/;

function validate(b: any) {
  const e: string[] = [];
  // Required consents
  if (b.consent_contact !== "1" && b.consent_contact !== 1 && b.consent_contact !== true) e.push("Kapcsolattartási hozzájárulás szükséges");
  if (b.consent_processing !== "1" && b.consent_processing !== 1 && b.consent_processing !== true) e.push("Adatkezelési hozzájárulás szükséges");

  // Minimal must-haves (tune as desired)
  ["nev_vezetek","nev_kereszt","szuletesi_datum","telefon","email"].forEach(k => { if (!required(b[k])) e.push(`${k} kötelező`); });
  if (b.szuletesi_datum && !dateRe.test(b.szuletesi_datum)) e.push("Dátum formátum: yyyy-mm-dd");
  if (b.telefon && !phoneRe.test((b.telefon+"").replaceAll("-", " ").trim())) e.push("Telefonszám formátum hibás");

  const toBool = (x:any)=> x===true || x==="true" || x==="1" || x===1;
  const toInt = (x:any)=> (x==null||x==="")? null : parseInt(x,10);

  return {
    valid: e.length===0,
    errors: e,
    data: {
      nev_elotag: b.nev_elotag ?? "",
      nev_vezetek: b.nev_vezetek ?? "",
      nev_kereszt: b.nev_kereszt ?? "",
      nev_utonev: b.nev_utonev ?? "",
      szuletesi_nev: b.szuletesi_nev ?? "",
      szuletesi_orszag: b.szuletesi_orszag ?? "",
      szuletesi_telepules: b.szuletesi_telepules ?? "",
      szuletesi_datum: b.szuletesi_datum ?? "",
      anya_leanykori_nev: b.anya_leanykori_nev ?? "",
      apa_neve: b.apa_neve ?? "",
      foglalkozas: b.foglalkozas ?? "",
      keresztelo_felekezet: b.keresztelo_felekezet ?? "",
      helyben_keresztelt: toBool(b.helyben_keresztelt)?1:0,
      keresztseg_helye: b.keresztseg_helye ?? "",
      keresztseg_eve: toInt(b.keresztseg_eve),
      konfirmalt: toBool(b.konfirmalt)?1:0,
      konfirmalo_felekezet: b.konfirmalo_felekezet ?? "",
      helyben_konfirmalt: toBool(b.helyben_konfirmalt)?1:0,
      konfirmacio_helye: b.konfirmacio_helye ?? "",
      konfirmacio_eve: toInt(b.konfirmacio_eve),
      hazas: toBool(b.hazas)?1:0,
      nem_hazas_statusz: b.nem_hazas_statusz ?? "",
      helyben_hazassag: toBool(b.helyben_hazassag)?1:0,
      hazassag_helye: b.hazassag_helye ?? "",
      hazassag_eve: toInt(b.hazassag_eve),
      hazastars_neve: b.hazastars_neve ?? "",
      irsz: b.irsz ?? "",
      varos: b.varos ?? "",
      utca_hazszam: b.utca_hazszam ?? "",
      epulet_emelet_ajto: b.epulet_emelet_ajto ?? "",
      telefon: (b.telefon ?? "").trim(),
      email: (b.email ?? "").trim(),
      nem_zugloi_tag_helyi_egyhaz: b.nem_zugloi_tag_helyi_egyhaz ?? "",
      consent_contact: toBool(b.consent_contact)?1:0,
      consent_processing: toBool(b.consent_processing)?1:0,
      hely: b.hely ?? "",
      datum: b.datum ?? "",
      alairas: b.alairas ?? "",
    }
  };
}

function toCSV(rows: any[]): string {
  if (!rows.length) return "id\n";
  const headers = Object.keys(rows[0]);
  const csv = [headers.join(",")];
  for (const r of rows) {
    csv.push(headers.map(h => {
      const v = r[h] ?? "";
      const s = typeof v === "string" ? v : JSON.stringify(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s;
    }).join(","));
  }
  return csv.join("\n");
}

/** Single-file, TailwindCDN, minimal + modern */
function indexHTML(){
  return `<!doctype html><html lang="hu"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Tagnyilvántartási adatlap</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 text-slate-900">
<main class="max-w-3xl mx-auto p-6 md:p-8">
  <h1 class="text-2xl font-semibold mb-2">Tagnyilvántartási adatlap</h1>
  <p class="text-sm text-slate-600 mb-6">Kérjük, pontosan töltse ki az alábbi űrlapot. A * jelölt mezők kötelezők.</p>

  <form id="f" class="grid gap-6 bg-white/90 backdrop-blur rounded-2xl shadow-lg p-6 md:p-8">
    <!-- Honeypot -->
    <input name="website" class="hidden" tabindex="-1" autocomplete="off">

    <!-- Személyes -->
    <section class="grid gap-4 md:grid-cols-2">
      <div class="md:col-span-2">
        <label class="label">Név *</label>
        <input name="nev" required class="input" placeholder="Vezetéknév Keresztnév">
      </div>
      <div class="md:col-span-2">
        <label class="label">Születési név</label>
        <input name="szuletesi_nev" class="input">
      </div>
      <div>
        <label class="label">Születési ország</label>
        <input name="szuletesi_orszag" class="input">
      </div>
      <div>
        <label class="label">Születési település</label>
        <input name="szuletesi_telepules" class="input">
      </div>
      <div>
        <label class="label">Születési idő *</label>
        <input type="date" name="szuletesi_datum" required class="input">
      </div>
      <div>
        <label class="label">Édesanyja leánykori neve</label>
        <input name="anyja_leanykori_nev" class="input">
      </div>
      <div>
        <label class="label">Édesapja neve</label>
        <input name="apa_neve" class="input">
      </div>
      <div class="md:col-span-2">
        <label class="label">Foglalkozás</label>
        <input name="foglalkozas" class="input">
      </div>
    </section>

    <h2 class="section">Keresztség</h2>
    <section class="grid gap-4 md:grid-cols-2">
      <div>
        <label class="label">Felekezet</label>
        <select name="keresztelo_felekezet" class="input">
          <option value=""></option><option>Evangélikus</option><option>Református</option><option>Római katolikus</option><option>Egyéb</option>
        </select>
      </div>
      <div>
        <label class="label">Helyben keresztelt?</label>
        <select name="helyben_keresztelt" class="input"><option value=""></option><option value="1">Igen</option><option value="0">Nem</option></select>
      </div>
      <div>
        <label class="label">Ha nem, hol?</label>
        <input name="keresztseg_helye" class="input">
      </div>
      <div>
        <label class="label">Keresztelés éve</label>
        <input type="number" name="keresztseg_eve" class="input" placeholder="YYYY">
      </div>
    </section>

    <h2 class="section">Konfirmáció</h2>
    <section class="grid gap-4 md:grid-cols-2">
      <div>
        <label class="label">Konfirmált?</label>
        <select name="konfirmalt" class="input"><option value=""></option><option value="1">Igen</option><option value="0">Nem</option></select>
      </div>
      <div>
        <label class="label">Konfirmáló felekezet</label>
        <select name="konfirmalo_felekezet" class="input"><option value=""></option><option>Evangélikus</option><option>Református</option><option>Egyéb</option></select>
      </div>
      <div>
        <label class="label">Helyben konfirmált?</label>
        <select name="helyben_konfirmalt" class="input"><option value=""></option><option value="1">Igen</option><option value="0">Nem</option></select>
      </div>
      <div>
        <label class="label">Ha nem, hol?</label>
        <input name="konfirmacio_helye" class="input">
      </div>
      <div>
        <label class="label">Konfirmáció éve</label>
        <input type="number" name="konfirmacio_eve" class="input" placeholder="YYYY">
      </div>
    </section>

    <h2 class="section">Családi állapot</h2>
    <section class="grid gap-4 md:grid-cols-2">
      <div>
        <label class="label">Házas?</label>
        <select name="hazas" class="input"><option value=""></option><option value="1">Igen</option><option value="0">Nem</option></select>
      </div>
      <div>
        <label class="label">Ha nem házas (státusz)</label>
        <select name="nem_hazas_statusz" class="input">
          <option value=""></option><option>elvált</option><option>özvegy</option><option>hajadon</option><option>nőtlen</option>
        </select>
      </div>
      <div>
        <label class="label">Helyben kötött házasság?</label>
        <select name="helyben_hazassag" class="input"><option value=""></option><option value="1">Igen</option><option value="0">Nem</option></select>
      </div>
      <div>
        <label class="label">Ha nem, hol?</label>
        <input name="hazassag_helye" class="input">
      </div>
      <div>
        <label class="label">Házasságkötés éve</label>
        <input type="number" name="hazassag_eve" class="input" placeholder="YYYY">
      </div>
      <div>
        <label class="label">Házastárs neve</label>
        <input name="hazastars_neve" class="input">
      </div>
    </section>

    <h2 class="section">Lakcím</h2>
    <section class="grid gap-4 md:grid-cols-2">
      <div>
        <label class="label">Irányítószám</label>
        <input name="iranyitoszam" class="input" placeholder="1146">
      </div>
      <div>
        <label class="label">Város</label>
        <input name="varos" class="input" placeholder="Budapest">
      </div>
      <div class="md:col-span-2">
        <label class="label">Utca, házszám</label>
        <input name="utca_hazszam" class="input">
      </div>
      <div class="md:col-span-2">
        <label class="label">Épület, emelet, ajtó</label>
        <input name="epulet_emelet_ajto" class="input">
      </div>
    </section>

    <h2 class="section">Elérhetőségek</h2>
    <section class="grid gap-4 md:grid-cols-2">
      <div>
        <label class="label">Telefon *</label>
        <input name="telefon" required class="input" placeholder="06 1 123 4567">
      </div>
      <div>
        <label class="label">E-mail *</label>
        <input type="email" name="email" required class="input" placeholder="nev@example.com">
      </div>
    </section>

    <h2 class="section">Egyéb</h2>
    <section class="grid gap-4">
      <div>
        <label class="label">Amennyiben nem zuglói lakos, tagja-e a lakóhelye szerinti egyházközségnek is?</label>
        <input name="nem_zugloi_tag_helyi_egyhaz" class="input">
      </div>
      <div class="grid gap-2">
        <label class="inline-flex gap-2 items-center"><input type="checkbox" name="consent_contact" value="1" required><span>Hozzájárulok a kapcsolattartáshoz és tájékoztatókhoz *</span></label>
        <label class="inline-flex gap-2 items-center"><input type="checkbox" name="consent_processing" value="1" required><span>Megismertem és elfogadom az adatkezelési tájékoztatót *</span></label>
      </div>
      <!-- hely / dátum / aláírás intentionally removed -->
    </section>

    <button class="bg-slate-900 text-white rounded-xl px-5 py-2.5 shadow hover:opacity-90">Beküldés</button>
    <p id="msg" class="text-sm"></p>
  </form>
</main>

<style>
  .label{font-size:0.9rem; margin-bottom:0.25rem; display:block;}
  .input{
    width:100%; box-sizing:border-box;
    padding:0.6rem 0.8rem; border-radius:0.75rem;
    border:1px solid rgb(203 213 225);
    background: rgba(255,255,255,0.85);
    color:#0f172a;
  }
  .input:focus{
    outline:none; box-shadow:0 0 0 3px rgba(148,163,184,0.5);
  }
  .section{font-weight:600; margin-top:0.5rem;}
</style>

<script>
const f=document.getElementById('f'), msg=document.getElementById('msg');
f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const data=Object.fromEntries(new FormData(f).entries());
  msg.textContent="Küldés...";
  const res=await fetch('/api/submit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)});
  msg.textContent = res.ok ? "Sikeres beküldés. Köszönjük!" : "Hiba: "+(await res.text());
  if(res.ok) f.reset();
});
</script>
</body></html>`;
}
