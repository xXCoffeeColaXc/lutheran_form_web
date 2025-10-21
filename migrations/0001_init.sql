-- Members table
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  ip TEXT,
  user_agent TEXT,

  -- Személyes adatok
  nev TEXT,
  szuletesi_nev TEXT,
  szuletesi_orszag TEXT,
  szuletesi_telepules TEXT,
  szuletesi_datum TEXT,         -- ISO yyyy-mm-dd
  anyja_leanykori_nev TEXT,
  apa_neve TEXT,
  foglalkozas TEXT,

  -- Keresztség
  keresztelo_felekezet TEXT,    -- evangélikus/református/rk/egyéb
  helyben_keresztelt INTEGER,   -- 0/1
  keresztseg_helye TEXT,
  keresztseg_eve INTEGER,

  -- Konfirmáció
  konfirmalt INTEGER,           -- 0/1
  konfirmalo_felekezet TEXT,
  helyben_konfirmalt INTEGER,   -- 0/1
  konfirmacio_helye TEXT,
  konfirmacio_eve INTEGER,

  -- Családi állapot
  hazas INTEGER,                 -- 0/1
  nem_hazas_statusz TEXT,        -- elvalt/ozvegy/hajadon/notlen
  helyben_hazassag INTEGER,      -- 0/1
  hazassag_helye TEXT,
  hazassag_eve INTEGER,
  hazastars_neve TEXT,

  -- Lakcím
  iranyitoszam TEXT,
  varos TEXT,
  utca_hazszam TEXT,
  epulet_emelet_ajto TEXT,

  -- Elérhetőségek
  telefon TEXT,
  email TEXT,

  -- Egyéb
  nem_zugloi_tag_helyi_egyhaz TEXT,  -- szöveges igen/nem + megjegyzés

  -- Hozzájárulások
  consent_contact INTEGER NOT NULL,      -- 0/1
  consent_processing INTEGER NOT NULL,   -- 0/1

  hely TEXT,
  datum TEXT,               -- ISO yyyy-mm-dd
  alairas TEXT              -- gépelt név (később bővíthető rajzolt aláírással)
);

CREATE INDEX IF NOT EXISTS idx_members_created_at ON members(created_at);
