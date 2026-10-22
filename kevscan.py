#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kevscan — Scanner de vulnérabilités piloté par un CSV officiel
================================================================
Catalogue par défaut : CISA KEV (Known Exploited Vulnerabilities, CSV officiel)
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
Tout autre CSV avec colonnes cveID / vendorProject / product est accepté (--catalog).

Sources d'inventaire
  local      logiciels installés sur la machine (Windows / Linux / macOS)
  inventory  fichier CSV d'inventaire (colonnes name,version)
  network    ports ouverts + bannières de cibles AUTORISÉES (--authorized requis)
  web        interface web locale (lance les 3 modes ci-dessus depuis le navigateur)

Enrichissements
  --nvd   vérifie la version détectée (plages CPE) et récupère le score CVSS (API NVD)
  --epss  probabilité d'exploitation à 30 jours (API FIRST EPSS)

Rapport professionnel HTML : --out-html (+ --client, --brand, --auditor, --logo)

Exemples
  python kevscan.py update
  python kevscan.py local --nvd --epss --out-html rapport.html --client "ACME SAS"
  python kevscan.py inventory parc.csv --nvd --out-json res.json
  python kevscan.py network 192.168.1.0/24 --authorized --nvd
  python kevscan.py web

Dépendances : bibliothèque standard uniquement (Python 3.9+).
Outil défensif : détection par correspondance catalogue/version, aucun exploit.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import csv
import html
import io
import ipaddress
import json
import mimetypes
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

__version__ = "2.0.0"

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
CACHE_DIR = Path(os.environ.get("KEVSCAN_CACHE", Path.home() / ".cache" / "kevscan"))
CACHE_TTL = 24 * 3600
UA = f"kevscan/{__version__} (audit defensif)"

STOP = {"the", "for", "and", "of", "inc", "corp", "corporation", "ltd", "llc", "project",
        "foundation", "software", "server", "web", "a", "co", "group"}
ALIASES = {
    "httpd": "apache http server", "apache": "apache http server",
    "microsoft-iis": "microsoft iis internet information services",
    "openssh": "openbsd openssh", "nginx": "f5 nginx", "proftpd": "proftpd",
}
FIELD_ALIASES = {
    "cve": ("cveid", "cve", "cveidentifier", "id"),
    "vendor": ("vendorproject", "vendor"),
    "product": ("product",),
    "name": ("vulnerabilityname", "name", "title"),
    "date": ("dateadded", "published", "date"),
    "desc": ("shortdescription", "description", "summary"),
    "action": ("requiredaction", "action"),
    "due": ("duedate",),
    "ransom": ("knownransomwarecampaignuse", "ransomware"),
}

LOG_SINK = None  # callback optionnel (interface web)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)
    if LOG_SINK:
        LOG_SINK(msg)


# ----------------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------------

def toks(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def vcmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


@dataclass
class Item:
    name: str
    version: str = ""
    source: str = ""
    evidence: str = ""

    def __post_init__(self):
        low = self.name.lower()
        extra = " ".join(v for k, v in ALIASES.items() if k in low)
        self.tokens = set(toks(f"{self.name} {extra}")) - STOP


@dataclass
class Finding:
    item: Item
    entry: dict
    status: str = "à vérifier"
    cvss: float | None = None
    severity: str = ""
    epss: float | None = None
    pct: float | None = None


# ----------------------------------------------------------------------------
# Catalogue CSV officiel
# ----------------------------------------------------------------------------

def parse_catalog(text: str) -> list[dict]:
    rd = csv.DictReader(io.StringIO(text))
    norm = {re.sub(r"[^a-z0-9]", "", h.lower()): h for h in (rd.fieldnames or [])}
    cols = {k: next((norm[a] for a in al if a in norm), None) for k, al in FIELD_ALIASES.items()}
    if not cols["cve"] or not cols["product"]:
        raise SystemExit("CSV invalide : colonnes cveID / product introuvables.")
    out = []
    for r in rd:
        e = {k: ((r.get(c) or "").strip() if c else "") for k, c in cols.items()}
        e["_prod"] = set(toks(e["product"])) - STOP
        e["_vend"] = set(toks(e["vendor"])) - STOP
        if e["cve"] and e["_prod"]:
            out.append(e)
    return out


def load_catalog(path: str | None = None, force: bool = False) -> list[dict]:
    if path:
        raw = Path(path).read_bytes()
    else:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        f = CACHE_DIR / "kev.csv"
        if force or not f.exists() or time.time() - f.stat().st_mtime > CACHE_TTL:
            try:
                f.write_bytes(http_get(KEV_URL))
                log("[+] Catalogue CISA KEV mis à jour")
            except Exception as e:  # noqa: BLE001
                if not f.exists():
                    raise SystemExit(f"Téléchargement impossible : {e}")
                log(f"[!] Mise à jour impossible ({e}), cache utilisé")
        raw = f.read_bytes()
    cat = parse_catalog(raw.decode("utf-8-sig", errors="replace"))
    log(f"[+] {len(cat)} vulnérabilités chargées")
    return cat


# ----------------------------------------------------------------------------
# Collecte : inventaire local
# ----------------------------------------------------------------------------

def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def inv_windows() -> list[Item]:
    import winreg  # type: ignore
    items = [Item("Microsoft Windows", platform.version(), "os")]
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in paths:
        try:
            k = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(k)[0]):
            try:
                sk = winreg.OpenKey(k, winreg.EnumKey(k, i))
                name = winreg.QueryValueEx(sk, "DisplayName")[0]
            except OSError:
                continue
            try:
                ver = str(winreg.QueryValueEx(sk, "DisplayVersion")[0])
            except OSError:
                ver = ""
            items.append(Item(name, ver, "registre"))
    return items


def inv_linux() -> list[Item]:
    items = [Item("Linux kernel", platform.release().split("-")[0], "os")]
    if shutil.which("dpkg-query"):
        for line in run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]).splitlines():
            n, _, v = line.partition("\t")
            items.append(Item(n, v, "dpkg"))
    elif shutil.which("rpm"):
        for line in run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]).splitlines():
            n, _, v = line.partition("\t")
            items.append(Item(n, v, "rpm"))
    elif shutil.which("pacman"):
        for line in run(["pacman", "-Q"]).splitlines():
            n, _, v = line.partition(" ")
            items.append(Item(n, v, "pacman"))
    return items


def inv_macos() -> list[Item]:
    items = [Item("Apple macOS", platform.mac_ver()[0], "os")]
    try:
        data = json.loads(run(["system_profiler", "SPApplicationsDataType", "-json"]) or "{}")
        for a in data.get("SPApplicationsDataType", []):
            items.append(Item(a.get("_name", ""), a.get("version", ""), "applications"))
    except json.JSONDecodeError:
        pass
    return items


def inv_local() -> list[Item]:
    s = platform.system()
    if s == "Windows":
        return inv_windows()
    if s == "Darwin":
        return inv_macos()
    return inv_linux()


def inv_csv_text(text: str, label: str = "inventaire") -> list[Item]:
    rd = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    low = {h.lower().strip(): h for h in (rd.fieldnames or [])}
    nc = next((low[k] for k in ("name", "nom", "software", "logiciel", "displayname") if k in low), None)
    vc = next((low[k] for k in ("version", "displayversion") if k in low), None)
    if not nc:
        raise SystemExit("Inventaire : colonne 'name' introuvable.")
    hc = next((low[k] for k in ("host", "hostname", "machine") if k in low), None)
    return [Item(r[nc], ((r.get(vc) or "") if vc else "").strip(),
                 ((r.get(hc) if hc else "") or label)) for r in rd if r.get(nc)]


def inv_csv(path: str) -> list[Item]:
    return inv_csv_text(Path(path).read_text(encoding="utf-8-sig"), Path(path).name)


# ----------------------------------------------------------------------------
# Collecte : réseau (cibles autorisées uniquement)
# ----------------------------------------------------------------------------

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306,
                 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 9200}
TLS_PORTS = {443, 465, 993, 995, 8443}
BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-\.]*?)[/_ -]v?(\d+(?:\.\d+)+(?:[a-z]\d*)?)")
IGNORE = {"ssh", "http", "https", "smtp", "esmtp", "ftp", "tls", "ssl", "imap", "pop3",
          "version", "ready", "ubuntu", "debian", "chunked"}


def expand_targets(specs: list[str], allow_files: bool = True) -> list[str]:
    hosts: list[str] = []
    for s in specs:
        if allow_files and Path(s).is_file():
            lines = [l.strip() for l in Path(s).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
            hosts += expand_targets(lines, allow_files)
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.num_addresses > 65536:
                raise SystemExit("Plage trop large (max /16).")
            hosts += [str(h) for h in (list(net.hosts()) or [net.network_address])]
        except ValueError:
            hosts.append(s)
    return list(dict.fromkeys(hosts))


def grab(host: str, port: int, timeout: float):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        if port in HTTP_PORTS:
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\r\n".encode())
        return s.recv(2048).decode("latin-1", "replace")
    except OSError:
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def parse_banner(text: str) -> list[tuple[str, str]]:
    out = []
    for n, v in BANNER_RE.findall(text):
        n = n.strip("-._")
        if len(n) < 2 or n.lower() in IGNORE:
            continue
        out.append((n, v))
    return list(dict.fromkeys(out))


def scan_network(hosts: list[str], ports: list[int], timeout: float, threads: int) -> list[Item]:
    items: list[Item] = []
    jobs = [(h, p) for h in hosts for p in ports]
    log(f"[+] {len(hosts)} hôte(s), {len(jobs)} sondes")
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(lambda hp: (hp, grab(hp[0], hp[1], timeout)), jobs))
    for (h, p), banner in results:
        if banner is None:
            continue
        log(f"  ouvert  {h}:{p}")
        first = banner.strip().splitlines()[0][:120] if banner.strip() else ""
        for n, v in parse_banner(banner):
            items.append(Item(n, v, f"{h}:{p}", first))
    return items


# ----------------------------------------------------------------------------
# Corrélation catalogue <-> inventaire
# ----------------------------------------------------------------------------

def correlate(items: list[Item], catalog: list[dict]) -> list[Finding]:
    idx: dict[str, list[dict]] = {}
    for e in catalog:
        for t in e["_prod"]:
            idx.setdefault(t, []).append(e)
    res = []
    for it in items:
        seen = set()
        for t in it.tokens:
            for e in idx.get(t, ()):
                if e["cve"] in seen:
                    continue
                if e["_prod"] <= it.tokens and (e["_vend"] & it.tokens or len(e["_prod"]) >= 2):
                    seen.add(e["cve"])
                    res.append(Finding(it, e))
    return res


# ----------------------------------------------------------------------------
# NVD : plages de versions + CVSS
# ----------------------------------------------------------------------------

_nvd_last = 0.0


def parse_cvss(cve_obj: dict) -> tuple[float | None, str]:
    metrics = cve_obj.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lst = metrics.get(key) or []
        if not lst:
            continue
        m = next((x for x in lst if x.get("type") == "Primary"), lst[0])
        cd = m.get("cvssData", {}) or {}
        if cd.get("baseScore") is not None:
            sev = cd.get("baseSeverity") or m.get("baseSeverity") or ""
            return float(cd["baseScore"]), str(sev).upper()
    return None, ""


def nvd_get(cve: str, cache: dict):
    global _nvd_last
    if cve in cache:
        return cache[cve]
    key = os.environ.get("NVD_API_KEY")
    delay = 0.7 if key else 6.5
    wait = _nvd_last + delay - time.time()
    if wait > 0:
        time.sleep(wait)
    headers = {"User-Agent": UA}
    if key:
        headers["apiKey"] = key
    try:
        req = urllib.request.Request(NVD_URL.format(cve), headers=headers)
        data = json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:  # noqa: BLE001
        _nvd_last = time.time()
        return None
    _nvd_last = time.time()
    keys = ("criteria", "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding")
    matches: list[dict] = []
    score, sev = None, ""
    for v in data.get("vulnerabilities", [])[:1]:
        c = v.get("cve", {})
        score, sev = parse_cvss(c)
        for cfg in c.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        matches.append({k: m.get(k) for k in keys})
    cache[cve] = {"matches": matches, "cvss": score, "severity": sev}
    return cache[cve]


def check_version(tokens: set, version: str, matches: list[dict]):
    """True = affecté, False = hors plage, None = indéterminé."""
    iv = vkey(version)
    seen_product = False
    for m in matches:
        p = (m.get("criteria") or "").split(":")
        if len(p) < 6:
            continue
        prod = set(toks(p[4].replace("_", " "))) - STOP
        if not prod or not prod <= tokens:
            continue
        seen_product = True
        if not iv:
            return None
        if p[5] not in ("*", "-"):
            if vcmp(iv, vkey(p[5])) == 0:
                return True
            continue
        sI, sE = m.get("versionStartIncluding"), m.get("versionStartExcluding")
        eI, eE = m.get("versionEndIncluding"), m.get("versionEndExcluding")
        if not any((sI, sE, eI, eE)):
            return True
        ok = True
        if sI and vcmp(iv, vkey(sI)) < 0: ok = False
        if sE and vcmp(iv, vkey(sE)) <= 0: ok = False
        if eI and vcmp(iv, vkey(eI)) > 0: ok = False
        if eE and vcmp(iv, vkey(eE)) >= 0: ok = False
        if ok:
            return True
    return False if seen_product else None


def enrich(findings: list[Finding], max_nvd: int) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / "nvd.json"
    try:
        raw = json.loads(path.read_text()) if path.exists() else {}
    except json.JSONDecodeError:
        raw = {}
    cache = {k: v for k, v in raw.items() if isinstance(v, dict)}
    done = 0
    for f in sorted(findings, key=lambda x: not x.item.version):
        cve = f.entry["cve"]
        if cve not in cache:
            if done >= max_nvd:
                continue
            done += 1
            log(f"[nvd] {cve} ({done}/{max_nvd})")
        d = nvd_get(cve, cache)
        if not d:
            continue
        f.cvss, f.severity = d.get("cvss"), d.get("severity", "")
        if f.item.version:
            r = check_version(f.item.tokens, f.item.version, d.get("matches", []))
            f.status = {True: "AFFECTÉ", False: "non affecté", None: "à vérifier"}[r]
    path.write_text(json.dumps(cache))


# ----------------------------------------------------------------------------
# EPSS (FIRST.org)
# ----------------------------------------------------------------------------

def enrich_epss(findings: list[Finding]) -> None:
    cves = sorted({f.entry["cve"] for f in findings})
    scores: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        log(f"[epss] {i + len(chunk)}/{len(cves)}")
        try:
            data = json.loads(http_get(EPSS_URL.format(",".join(chunk)), 30))
        except Exception as e:  # noqa: BLE001
            log(f"[!] EPSS indisponible : {e}")
            continue
        for d in data.get("data", []):
            try:
                scores[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
            except (KeyError, ValueError):
                continue
    for f in findings:
        if f.entry["cve"] in scores:
            f.epss, f.pct = scores[f.entry["cve"]]


# ----------------------------------------------------------------------------
# Pipeline commun CLI / web
# ----------------------------------------------------------------------------

RANK = {"AFFECTÉ": 0, "à vérifier": 1, "non affecté": 2}


def sort_findings(fs: list[Finding]) -> list[Finding]:
    fs = sorted(fs, key=lambda f: f.entry["date"], reverse=True)
    fs = sorted(fs, key=lambda f: -(f.epss if f.epss is not None else -1))
    return sorted(fs, key=lambda f: (RANK[f.status], 0 if f.entry["ransom"].lower() == "known" else 1))


def pipeline(items, catalog, nvd=False, max_nvd=50, epss=False, show_all=False) -> list[Finding]:
    findings = correlate(items, catalog)
    log(f"[+] {len(findings)} correspondance(s) catalogue")
    if nvd:
        enrich(findings, max_nvd)
    if epss:
        enrich_epss(findings)
    if not show_all:
        findings = [f for f in findings if f.status != "non affecté"]
    return sort_findings(findings)


# ----------------------------------------------------------------------------
# Rapports
# ----------------------------------------------------------------------------

def row(f: Finding) -> dict:
    e, i = f.entry, f.item
    return {"statut": f.status, "cve": e["cve"], "vendeur": e["vendor"], "produit": e["product"],
            "vulnerabilite": e["name"], "date_ajout": e["date"], "echeance": e["due"],
            "ransomware": e["ransom"], "cvss": f.cvss, "severite": f.severity,
            "epss": f.epss, "epss_percentile": f.pct, "detecte": i.name,
            "version": i.version, "source": i.source, "action": e["action"]}


def print_report(fs: list[Finding]) -> None:
    for f in fs:
        e, i = f.entry, f.item
        rw = "  [RANSOMWARE]" if e["ransom"].lower() == "known" else ""
        print(f"[{f.status}] {e['cve']}  {e['vendor']} {e['product']}{rw}")
        print(f"   {e['name']}")
        print(f"   Détecté : {i.name} {i.version}  @ {i.source}")
        score = []
        if f.cvss is not None:
            score.append(f"CVSS {f.cvss} ({f.severity or '?'})")
        if f.epss is not None:
            score.append(f"EPSS {f.epss:.1%}")
        if score:
            print("   Score   : " + " · ".join(score))
        if e["action"]:
            print(f"   Action  : {e['action']}  (échéance {e['due']})")
        print()
    c = {s: sum(1 for f in fs if f.status == s) for s in RANK}
    print(f"Résumé : {c['AFFECTÉ']} affecté(s) · {c['à vérifier']} à vérifier · "
          f"{c['non affecté']} non affecté(s)")


def logo_uri(path: str | None) -> str:
    if not path:
        return ""
    mime = mimetypes.guess_type(path)[0] or "image/png"
    return f"data:{mime};base64," + base64.b64encode(Path(path).read_bytes()).decode()


def make_meta(client, brand, auditor, logo, source, n_items, catalog) -> dict:
    return {"client": client or "", "brand": brand or "Kapelgy", "auditor": auditor or "",
            "logo": logo or "", "source": source, "n_items": n_items, "catalog": catalog}


REPORT_CSS = """
@page{margin:16mm}
*{box-sizing:border-box}
body{font:13px/1.45 'Segoe UI',system-ui,sans-serif;color:#1b1f24;margin:0;padding:28px;background:#fff}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #0b3d91;padding-bottom:14px;margin-bottom:22px}
header img{height:46px;margin-right:14px}.brand{display:flex;align-items:center;font-size:20px;font-weight:700;color:#0b3d91}
.meta{text-align:right;color:#555;font-size:12px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;color:#0b3d91;margin:26px 0 10px;border-left:4px solid #0b3d91;padding-left:8px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.card{border:1px solid #d8dee6;border-radius:8px;padding:12px;text-align:center;background:#f7f9fc}
.card b{display:block;font-size:26px}.card.red b{color:#c62828}.card.amb b{color:#b26a00}
table{border-collapse:collapse;width:100%;font-size:11.5px}
th{background:#0b3d91;color:#fff;text-align:left;padding:6px 8px}td{border-bottom:1px solid #e3e8ef;padding:6px 8px;vertical-align:top}
tr:nth-child(even) td{background:#fafbfd}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}
.aff{background:#c62828}.chk{background:#b26a00}.ok{background:#2e7d32}.rw{background:#6a1b9a}
.note{color:#555;font-size:12px;border:1px solid #e3e8ef;background:#f7f9fc;padding:10px 12px;border-radius:6px}
@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def build_html(fs: list[Finding], meta: dict) -> str:
    e = html.escape
    rows = [row(f) for f in fs]
    n_aff = sum(r["statut"] == "AFFECTÉ" for r in rows)
    n_chk = sum(r["statut"] == "à vérifier" for r in rows)
    n_rw = sum(str(r["ransomware"]).lower() == "known" for r in rows)
    n_crit = sum((r["cvss"] or 0) >= 9 for r in rows)
    cls = {"AFFECTÉ": "aff", "à vérifier": "chk", "non affecté": "ok"}

    def badge(r):
        s = f"<span class='b {cls[r['statut']]}'>{e(r['statut'])}</span>"
        if str(r["ransomware"]).lower() == "known":
            s += " <span class='b rw'>ransomware</span>"
        return s

    def score(r):
        return "" if r["cvss"] is None else f"{r['cvss']} {e(r['severite'])}"

    def epss(r):
        return "" if r["epss"] is None else f"{r['epss']:.1%}"

    def line(r, full):
        cells = [badge(r), f"<b>{e(r['cve'])}</b>", e(f"{r['vendeur']} {r['produit']}"),
                 e(f"{r['detecte']} {r['version']}".strip())]
        if full:
            cells.append(e(r["source"]))
        cells += [score(r), epss(r), e(r["echeance"]), e(r["action"])]
        return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"

    def table(rs, full):
        heads = ["Statut", "CVE", "Produit (catalogue)", "Détecté"] + (["Source"] if full else []) + \
                ["CVSS", "EPSS", "Échéance CISA", "Action requise"]
        return ("<table><tr>" + "".join(f"<th>{h}</th>" for h in heads) + "</tr>" +
                "".join(line(r, full) for r in rs) + "</table>") if rs else "<p>Aucun résultat.</p>"

    prio = [r for r in rows if r["statut"] != "non affecté"][:10]
    logo = f"<img src='{e(meta['logo'])}' alt=''>" if meta.get("logo") else ""
    client = f"<h1>{e(meta['client'])}</h1>" if meta.get("client") else ""
    auditor = f"<div>Auditeur : {e(meta['auditor'])}</div>" if meta.get("auditor") else ""
    return (
        "<!doctype html><html lang='fr'><meta charset='utf-8'><title>Rapport de vulnérabilités</title>"
        f"<style>{REPORT_CSS}</style>"
        f"<header><div class='brand'>{logo}{e(meta['brand'])}</div>"
        f"<div class='meta'><div>Rapport de vulnérabilités</div>"
        f"<div>{time.strftime('%d/%m/%Y %H:%M')}</div>{auditor}</div></header>"
        f"{client}<div class='note'>Périmètre : {e(meta['source'])} — {meta['n_items']} élément(s) "
        f"inventorié(s) — catalogue : {e(meta['catalog'])}</div>"
        "<h2>Synthèse</h2><div class='cards'>"
        f"<div class='card red'><b>{n_aff}</b>affectée(s)</div>"
        f"<div class='card amb'><b>{n_chk}</b>à vérifier</div>"
        f"<div class='card red'><b>{n_rw}</b>liée(s) à des ransomwares</div>"
        f"<div class='card red'><b>{n_crit}</b>CVSS ≥ 9</div>"
        f"<div class='card'><b>{len(rows)}</b>au total</div></div>"
        "<h2>Priorités de remédiation (top 10)</h2>" + table(prio, False) +
        "<h2>Détail complet</h2>" + table(rows, True) +
        "<h2>Méthodologie et limites</h2><div class='note'>Les vulnérabilités proviennent du catalogue "
        "CISA KEV (failles exploitées activement). La corrélation repose sur le nom du produit ; "
        "« AFFECTÉ » signifie que la version détectée est dans la plage affectée selon la NVD, "
        "« à vérifier » que la version n'a pas pu être confirmée. Le score EPSS estime la probabilité "
        "d'exploitation à 30 jours. Ce rapport ne remplace pas un test d'intrusion.</div></html>")


def write_reports(fs: list[Finding], a, meta: dict) -> None:
    rows = [row(f) for f in fs]
    if a.out_json:
        Path(a.out_json).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.out_csv and rows:
        with open(a.out_csv, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    if a.out_html:
        Path(a.out_html).write_text(build_html(fs, meta), encoding="utf-8")


def rows_to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return "\ufeff" + buf.getvalue()


# ----------------------------------------------------------------------------
# Interface web locale
# ----------------------------------------------------------------------------

WEB_HTML = r"""<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>kevscan</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#667;--bd:#d9dde3;--card:#f5f7fa;--acc:#1f4fd8;--red:#c62828;--amb:#b26a00;--grn:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8e8e8;--mut:#9aa3ad;--bd:#333a44;--card:#1c1f25;--acc:#6b93ff;--red:#ff7b7b;--amb:#ffb454;--grn:#6fcf7f}}
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:20px;max-width:1250px;margin-inline:auto}
h1{margin:0 0 4px}.sub{color:var(--mut);margin-bottom:16px}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
label{display:block;font-size:12px;color:var(--mut);margin-bottom:3px}
input,select,textarea{width:100%;padding:7px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
button{padding:9px 18px;border:0;border-radius:6px;background:var(--acc);color:#fff;font-weight:600;cursor:pointer}
button:disabled{opacity:.5}.chk{display:inline-flex;align-items:center;gap:6px;margin-right:14px;color:var(--fg);font-size:13px}.chk input{width:auto}
pre{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px;max-height:150px;overflow:auto;font-size:12px;margin:10px 0 0}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card)}.wrap{overflow-x:auto}
.b{padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}.aff{background:var(--red)}.cka{background:var(--amb)}.ok{background:var(--grn)}.rw{background:#7b1fa2}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}.c{flex:1;min-width:110px;border:1px solid var(--bd);border-radius:8px;padding:8px;text-align:center}.c b{display:block;font-size:22px}
a.dl{color:var(--acc);margin-right:14px}
</style>
<h1>kevscan</h1><div class="sub">Scanner de vulnérabilités basé sur le CSV officiel CISA KEV — interface locale</div>
<div class="panel">
 <div class="grid">
  <div><label>Source</label><select id="mode" onchange="mode()">
   <option value="local">Cette machine (inventaire local)</option>
   <option value="inventory">Fichier CSV d'inventaire</option>
   <option value="network">Scan réseau (cibles autorisées)</option></select></div>
  <div><label>Client (rapport)</label><input id="client" placeholder="ACME SAS"></div>
  <div><label>Marque</label><input id="brand" value="Kapelgy"></div>
  <div><label>Auditeur</label><input id="auditor"></div>
 </div>
 <div id="f-inventory" style="display:none;margin-top:10px"><label>CSV (colonnes name,version[,host])</label><input type="file" id="file" accept=".csv"></div>
 <div id="f-network" style="display:none;margin-top:10px"><div class="grid">
  <div><label>Cibles (IP, CIDR, hôtes — séparés par espace/virgule)</label><textarea id="targets" rows="2" placeholder="192.168.1.0/24"></textarea></div>
  <div><label>Ports (vide = liste courante)</label><input id="ports" placeholder="22,80,443"></div></div>
  <label class="chk" style="margin-top:8px"><input type="checkbox" id="auth"> Je confirme avoir l'autorisation écrite de scanner ces cibles</label></div>
 <div style="margin:12px 0"><label class="chk"><input type="checkbox" id="nvd" checked> Vérifier versions + CVSS (NVD, lent sans clé API)</label>
  <label class="chk"><input type="checkbox" id="epss" checked> EPSS</label>
  <label class="chk"><input type="checkbox" id="all"> Afficher les « non affecté »</label></div>
 <button id="btn" onclick="start()">Lancer le scan</button><pre id="log">Prêt.</pre>
</div>
<div id="res" style="display:none">
 <div class="cards" id="cards"></div>
 <div class="panel"><div style="margin-bottom:8px">
  <a class="dl" data-p="/report.html">Rapport HTML</a><a class="dl" data-p="/report.csv">CSV</a><a class="dl" data-p="/report.json">JSON</a></div>
  <div class="grid" style="margin-bottom:8px"><input id="q" placeholder="Filtrer (CVE, produit…)" oninput="render()">
   <select id="st" onchange="render()"><option value="">Tous statuts</option><option>AFFECTÉ</option><option>à vérifier</option><option>non affecté</option></select></div>
  <div class="wrap"><table><thead><tr><th>Statut</th><th>CVE</th><th>Produit</th><th>Détecté</th><th>CVSS</th><th>EPSS</th><th>Échéance</th><th>Source</th></tr></thead><tbody id="tb"></tbody></table></div></div>
</div>
<script>
const T="__TOKEN__";const $=s=>document.querySelector(s);let rows=[];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
document.querySelectorAll("a.dl").forEach(a=>a.href=a.dataset.p+"?t="+encodeURIComponent(T));
function mode(){const m=$("#mode").value;for(const k of["inventory","network"])$("#f-"+k).style.display=m===k?"block":"none"}
async function start(){
 const b={mode:$("#mode").value,nvd:$("#nvd").checked,epss:$("#epss").checked,all:$("#all").checked,client:$("#client").value,brand:$("#brand").value,auditor:$("#auditor").value,targets:$("#targets").value,ports:$("#ports").value,authorized:$("#auth").checked};
 if(b.mode==="inventory"){const f=$("#file").files[0];if(!f){alert("Choisissez un fichier CSV");return}b.csv=await f.text()}
 const r=await fetch("/api/scan",{method:"POST",headers:{"X-Token":T,"Content-Type":"application/json"},body:JSON.stringify(b)});
 const j=await r.json();if(!r.ok){alert(j.error||"Erreur");return}
 $("#btn").disabled=true;$("#res").style.display="none";poll()}
async function poll(){
 const j=await(await fetch("/api/job",{headers:{"X-Token":T}})).json();
 $("#log").textContent=(j.log||[]).join("\n");$("#log").scrollTop=1e9;
 if(j.status==="running"){setTimeout(poll,1500);return}
 $("#btn").disabled=false;
 if(j.status==="error"){$("#log").textContent+="\nERREUR : "+j.error;return}
 rows=j.rows||[];$("#res").style.display="block";render()}
function render(){
 const q=$("#q").value.toLowerCase(),st=$("#st").value;
 const n=s=>rows.filter(r=>r.statut===s).length;
 $("#cards").innerHTML=[["AFFECTÉ",n("AFFECTÉ")],["à vérifier",n("à vérifier")],["ransomware",rows.filter(r=>String(r.ransomware).toLowerCase()==="known").length],["CVSS ≥ 9",rows.filter(r=>(r.cvss||0)>=9).length],["total",rows.length]].map(([l,v])=>`<div class="c"><b>${v}</b>${l}</div>`).join("");
 const cl={"AFFECTÉ":"aff","à vérifier":"cka","non affecté":"ok"};
 $("#tb").innerHTML=rows.filter(r=>(!st||r.statut===st)&&(!q||JSON.stringify(r).toLowerCase().includes(q))).map(r=>
  `<tr><td><span class="b ${cl[r.statut]}">${esc(r.statut)}</span>${String(r.ransomware).toLowerCase()==="known"?' <span class="b rw">ransomware</span>':""}</td><td><b>${esc(r.cve)}</b></td><td>${esc(r.vendeur+" "+r.produit)}</td><td>${esc((r.detecte+" "+r.version).trim())}</td><td>${r.cvss==null?"":esc(r.cvss+" "+r.severite)}</td><td>${r.epss==null?"":(r.epss*100).toFixed(1)+"%"}</td><td>${esc(r.echeance)}</td><td>${esc(r.source)}</td></tr>`).join("")}
</script></html>"""


def run_job(srv, job: dict, params: dict) -> None:
    global LOG_SINK
    LOG_SINK = lambda m: job["log"].append(m)  # noqa: E731
    try:
        mode = params["mode"]
        if mode == "local":
            items, label = inv_local(), "machine locale"
        elif mode == "inventory":
            items, label = inv_csv_text(params.get("csv", "")), "inventaire CSV"
        else:
            ports = [int(p) for p in re.findall(r"\d+", params.get("ports") or "")] or DEFAULT_PORTS
            targets = [t for t in re.split(r"[\s,;]+", params.get("targets", "")) if t]
            items, label = scan_network(expand_targets(targets, allow_files=False), ports, 2.0, 100), "scan réseau"
        log(f"[+] {len(items)} élément(s) inventorié(s)")
        fs = pipeline(items, srv.catalog, bool(params.get("nvd")), 50,
                      bool(params.get("epss")), bool(params.get("all")))
        job["findings"], job["rows"] = fs, [row(f) for f in fs]
        job["meta"] = make_meta(params.get("client"), params.get("brand"), params.get("auditor"),
                                "", label, len(items), srv.catalog_name)
        job["status"] = "done"
    except SystemExit as e:
        job["error"], job["status"] = str(e.code), "error"
    except Exception as e:  # noqa: BLE001
        job["error"], job["status"] = f"{type(e).__name__}: {e}", "error"
    finally:
        LOG_SINK = None


class WebHandler(BaseHTTPRequestHandler):
    server_version = "kevscan"

    def log_message(self, *a):  # silence
        pass

    def _host_ok(self) -> bool:
        h = self.headers.get("Host", "")
        host = h.split("]")[0] + "]" if h.startswith("[") else h.split(":")[0]
        return host in self.server.allowed

    def _token_ok(self) -> bool:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        t = self.headers.get("X-Token") or (q.get("t") or [""])[0]
        return secrets.compare_digest(t, self.server.token)

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "hôte refusé"})
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(200, WEB_HTML.replace("__TOKEN__", self.server.token), "text/html; charset=utf-8",
                              {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
        if not self._token_ok():
            return self._json(403, {"error": "jeton invalide"})
        job = self.server.job
        if path == "/api/job":
            return self._json(200, {"status": job["status"], "log": job["log"][-300:],
                                    "rows": job["rows"] if job["status"] == "done" else [],
                                    "error": job["error"]})
        if job["status"] == "done" and path in ("/report.html", "/report.csv", "/report.json"):
            dl = lambda n: {"Content-Disposition": f'attachment; filename="{n}"'}  # noqa: E731
            if path == "/report.html":
                return self._send(200, build_html(job["findings"], job["meta"]), "text/html; charset=utf-8",
                                  dl("rapport-kevscan.html"))
            if path == "/report.csv":
                return self._send(200, rows_to_csv(job["rows"]), "text/csv; charset=utf-8", dl("kevscan.csv"))
            return self._send(200, json.dumps(job["rows"], ensure_ascii=False, indent=2), headers=dl("kevscan.json"))
        self._json(404, {"error": "introuvable"})

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "hôte refusé"})
        if urllib.parse.urlparse(self.path).path != "/api/scan":
            return self._json(404, {"error": "introuvable"})
        if not self._token_ok():
            return self._json(403, {"error": "jeton invalide"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 5_000_000:
            return self._json(413, {"error": "fichier trop volumineux (5 Mo max)"})
        try:
            params = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "JSON invalide"})
        if params.get("mode") not in ("local", "inventory", "network"):
            return self._json(400, {"error": "mode invalide"})
        if params["mode"] == "network" and not params.get("authorized"):
            return self._json(400, {"error": "Confirmez l'autorisation de scanner ces cibles."})
        srv = self.server
        with srv.lock:
            if srv.job["status"] == "running":
                return self._json(409, {"error": "un scan est déjà en cours"})
            srv.job = {"status": "running", "log": [], "rows": [], "findings": [], "meta": {}, "error": ""}
            threading.Thread(target=run_job, args=(srv, srv.job, params), daemon=True).start()
        self._json(200, {"ok": True})


def serve(a) -> int:
    if a.host not in ("127.0.0.1", "localhost") and not a.allow_remote:
        raise SystemExit("Écoute hors loopback refusée : ajoutez --allow-remote (à vos risques).")
    catalog = load_catalog(a.catalog, a.refresh)
    srv = ThreadingHTTPServer((a.host, a.port), WebHandler)
    srv.token = secrets.token_urlsafe(16)
    srv.lock = threading.Lock()
    srv.catalog = catalog
    srv.catalog_name = Path(a.catalog).name if a.catalog else "CISA KEV"
    srv.allowed = {"127.0.0.1", "localhost", "[::1]", a.host}
    srv.job = {"status": "idle", "log": [], "rows": [], "findings": [], "meta": {}, "error": ""}
    print(f"kevscan web → http://{a.host}:{a.port}/   (Ctrl+C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="kevscan — scanner basé sur un CSV officiel (CISA KEV)")
    ap.add_argument("--version", action="version", version=f"kevscan {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def catalog_args(p):
        p.add_argument("--catalog", help="CSV de vulnérabilités (défaut : CISA KEV officiel)")
        p.add_argument("--refresh", action="store_true", help="force le re-téléchargement du catalogue")

    def common(p):
        catalog_args(p)
        p.add_argument("--nvd", action="store_true", help="vérifie versions + CVSS via l'API NVD")
        p.add_argument("--max-nvd", type=int, default=50, help="requêtes NVD max (défaut 50)")
        p.add_argument("--epss", action="store_true", help="ajoute le score EPSS (FIRST)")
        p.add_argument("--all", action="store_true", help="affiche aussi les 'non affecté'")
        p.add_argument("--out-json"); p.add_argument("--out-csv")
        p.add_argument("--out-html", help="rapport HTML professionnel")
        p.add_argument("--client", help="nom du client (rapport)")
        p.add_argument("--brand", default="Kapelgy", help="marque affichée dans le rapport")
        p.add_argument("--auditor", help="nom de l'auditeur (rapport)")
        p.add_argument("--logo", help="image du logo (PNG/SVG/JPG) intégrée au rapport")

    catalog_args(sub.add_parser("update", help="met à jour le catalogue CISA KEV"))
    common(sub.add_parser("local", help="inventaire local de la machine"))
    pi = sub.add_parser("inventory", help="inventaire depuis un CSV (name,version)")
    pi.add_argument("file"); common(pi)
    pn = sub.add_parser("network", help="scan réseau de cibles autorisées")
    pn.add_argument("targets", nargs="+", help="IP, CIDR, nom d'hôte ou fichier de cibles")
    pn.add_argument("--authorized", action="store_true", help="confirme l'autorisation écrite de scanner")
    pn.add_argument("--ports", help="ports, ex: 22,80,443 (défaut : liste courante)")
    pn.add_argument("--timeout", type=float, default=2.0)
    pn.add_argument("--threads", type=int, default=100)
    common(pn)
    pw = sub.add_parser("web", help="interface web locale")
    catalog_args(pw)
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=8765)
    pw.add_argument("--allow-remote", action="store_true", help="autorise l'écoute hors loopback")
    a = ap.parse_args()

    if a.cmd == "update":
        load_catalog(None, force=True)
        return 0
    if a.cmd == "web":
        return serve(a)

    catalog = load_catalog(a.catalog, a.refresh)
    if a.cmd == "local":
        items, label = inv_local(), "machine locale"
    elif a.cmd == "inventory":
        items, label = inv_csv(a.file), a.file
    else:
        if not a.authorized:
            raise SystemExit("Scan réseau : ajoutez --authorized pour confirmer que vous avez "
                             "l'autorisation écrite de tester ces cibles.")
        ports = [int(p) for p in a.ports.split(",")] if a.ports else DEFAULT_PORTS
        items = scan_network(expand_targets(a.targets), ports, a.timeout, a.threads)
        label = "scan réseau : " + ", ".join(a.targets)

    log(f"[+] {len(items)} élément(s) inventorié(s)")
    findings = pipeline(items, catalog, a.nvd, a.max_nvd, a.epss, a.all)
    print_report(findings)
    meta = make_meta(a.client, a.brand, a.auditor, logo_uri(a.logo), label, len(items),
                     Path(a.catalog).name if a.catalog else "CISA KEV")
    write_reports(findings, a, meta)
    return 1 if any(f.status == "AFFECTÉ" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
