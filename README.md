# kevscan

[![CI](https://github.com/Gabriel-temstet/kevscan/actions/workflows/ci.yml/badge.svg)](https://github.com/VOTRE-COMPTE/kevscan/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances-aucune-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

Scanner de vulnérabilités **piloté par un CSV officiel** : par défaut le catalogue
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (*Known Exploited Vulnerabilities*,
failles exploitées activement). Un seul fichier Python, **aucune dépendance** (bibliothèque standard).

kevscan croise un inventaire (logiciels installés, fichier CSV ou bannières réseau) avec le catalogue, confirme
les versions via la NVD, priorise avec CVSS et EPSS, puis produit un rapport client prêt à envoyer.

> **Outil défensif.** kevscan détecte par correspondance catalogue/version. Il n'embarque aucun exploit et ne
> tente aucune exploitation.

## Fonctionnalités

| | |
|---|---|
| **Catalogue officiel** | Téléchargement et cache 24 h du CSV CISA KEV ; tout CSV avec `cveID`, `vendorProject`, `product` est accepté (`--catalog`) |
| **3 sources d'inventaire** | `local` (Windows, Linux dpkg/rpm/pacman, macOS), `inventory` (CSV `name,version[,host]`), `network` (ports + bannières) |
| **Vérification de version** | API NVD : la version détectée est comparée aux plages CPE (`AFFECTÉ` / `à vérifier` / `non affecté`) |
| **Priorisation** | Score **CVSS** (NVD) et **EPSS** (FIRST), indicateur d'usage par des ransomwares, échéance CISA |
| **Rapport professionnel** | HTML imprimable en PDF : synthèse, top 10 des priorités, détail, méthodologie ; marque, client, auditeur et logo personnalisables |
| **Interface web locale** | `kevscan web` : lancement des scans, filtres, téléchargement HTML/CSV/JSON |
| **Intégration CI/CD** | Code de sortie `1` si au moins une vulnérabilité est `AFFECTÉ` |

## Installation

```bash
git clone https://github.com/VOTRE-COMPTE/kevscan.git
cd kevscan
python kevscan.py --help      # Python 3.9+, rien à installer
```

## Utilisation

```bash
# Mettre à jour le catalogue CISA KEV
python kevscan.py update

# Machine locale, avec versions + CVSS + EPSS, rapport pour un client
python kevscan.py local --nvd --epss --out-html rapport.html \
    --client "ACME SAS" --auditor "Prénom Nom" --logo logo.png

# Parc exporté en CSV
python kevscan.py inventory examples/inventaire.csv --nvd --out-json resultats.json

# Réseau (cibles AUTORISÉES uniquement)
python kevscan.py network 192.168.1.0/24 --authorized --ports 22,80,443,8080 --nvd

# Interface web (http://127.0.0.1:8765)
python kevscan.py web
```

### Options communes

| Option | Rôle |
|---|---|
| `--catalog FICHIER.csv` | Utilise un autre CSV de vulnérabilités |
| `--refresh` | Force le re-téléchargement du catalogue |
| `--nvd` | Vérifie la version et récupère le CVSS (API NVD) |
| `--max-nvd N` | Plafonne le nombre de requêtes NVD (défaut 50) |
| `--epss` | Ajoute la probabilité d'exploitation à 30 jours |
| `--all` | Affiche aussi les correspondances `non affecté` |
| `--out-json` / `--out-csv` / `--out-html` | Exports |
| `--client`, `--brand`, `--auditor`, `--logo` | Personnalisation du rapport |

### Format de l'inventaire CSV

```csv
host,name,version
SRV-WEB01,Apache HTTP Server,2.4.49
SRV-WEB01,OpenSSH,8.2p1
```

Les colonnes `name` (ou `nom`, `software`, `logiciel`, `displayname`) et `version` sont reconnues ; `host` est optionnelle.

### Format d'un catalogue personnalisé

Colonnes minimales : `cveID` et `product`. Colonnes reconnues en plus : `vendorProject`, `vulnerabilityName`,
`dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`.
Voir `examples/catalogue-exemple.csv`.

## Comment les résultats sont calculés

1. Le nom du produit détecté est découpé en mots-clés puis comparé au produit (et au vendeur) du catalogue.
2. Avec `--nvd`, les plages de versions CPE de la CVE sont comparées à la version détectée.
3. Les résultats sont triés : statut, usage ransomware, EPSS décroissant, date d'ajout.

| Statut | Signification |
|---|---|
| `AFFECTÉ` | Version détectée dans la plage affectée selon la NVD |
| `à vérifier` | Produit correspondant, version non confirmée (absente, ou NVD non interrogée) |
| `non affecté` | Version hors plage (masqué sauf `--all`) |

## Limites

- Le CSV KEV ne contient **pas** de plages de versions : sans `--nvd`, tout reste « à vérifier ».
- KEV ne liste que les failles **exploitées activement**, pas toutes les CVE. Pour une couverture plus large,
  fournissez un autre CSV avec `--catalog`.
- La correspondance se fait sur les noms de produits : prévoir des faux positifs et négatifs (noms de paquets
  Linux différents des noms CPE, par exemple). Les alias de `kevscan.py` (`ALIASES`) sont extensibles.
- Le scan réseau repose sur les bannières : un service qui masque sa version ne sera pas détecté.
- Sans clé API, la NVD limite à environ 5 requêtes par 30 s. Une clé gratuite accélère nettement le scan :
  `export NVD_API_KEY=...`.

## Sécurité et usage responsable

- Le mode `network` exige `--authorized` : ne scannez que des systèmes pour lesquels vous disposez d'une
  **autorisation écrite**.
- L'interface web écoute sur `127.0.0.1` uniquement (l'écoute distante demande `--allow-remote`). Elle exige un
  jeton de session, vérifie l'en-tête `Host` (protection DNS rebinding) et refuse la lecture de fichiers locaux
  comme cibles. Ne l'exposez pas sur Internet.
- Les données envoyées à l'extérieur se limitent aux identifiants CVE (NVD, EPSS) : jamais votre inventaire.

## Variables d'environnement

| Variable | Rôle |
|---|---|
| `NVD_API_KEY` | Clé API NVD (requêtes plus rapides) |
| `KEVSCAN_CACHE` | Répertoire du cache (défaut `~/.cache/kevscan`) |

## Intégration continue

```yaml
- name: Scan des vulnérabilités connues exploitées
  run: python kevscan.py inventory parc.csv --nvd --out-html rapport.html
  # échoue (code 1) si une vulnérabilité est AFFECTÉ
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Structure du dépôt

```
kevscan.py                      # scanner, rapport et interface web (fichier unique)
examples/inventaire.csv         # inventaire d'exemple
examples/catalogue-exemple.csv  # mini catalogue pour tester hors ligne
tests/test_kevscan.py           # tests unitaires
.github/workflows/ci.yml        # CI Python 3.9 à 3.12
```

## Licence

MIT, voir [LICENSE](LICENSE). Données : CISA KEV (domaine public américain), NVD (NIST), EPSS (FIRST).
