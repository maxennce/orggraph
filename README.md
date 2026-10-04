# OrgGraph

**Passive OSINT Intelligence & Correlation Framework**

OrgGraph est un outil OSINT passif permettant de cartographier l'écosystème public d'une organisation à partir d'un simple nom de domaine.

Il collecte plusieurs signaux publics, les normalise en entités et relations, puis les corrèle afin de construire une vue structurée de l'infrastructure observée.

```text
target domain
     │
     ├── DNS
     ├── Certificate Transparency
     ├── RDAP
     └── HTTP
           │
           ▼
      Observations
           │
           ▼
        Entities
           │
           ▼
      Relationships
           │
           ▼
         Scoring
           │
           ▼
     SQLite / Graph
```

OrgGraph conserve également l'historique des scans afin de comparer les changements observés au fil du temps.

---

## Features

- Passive domain reconnaissance
- DNS enumeration
- Certificate Transparency discovery
- RDAP lookup
- Basic HTTP intelligence
- Entity normalization
- Relationship correlation
- Explainable confidence scoring
- Scan history
- Diff between scans
- Timeline
- JSON export
- Interactive local web interface
- Graph visualization
- Machine-readable JSON mode
- Individual collectors can fail without stopping the scan

---

## Data sources

OrgGraph utilise uniquement des sources et informations publiquement accessibles.

### DNS

Records actuellement pris en charge :

```text
A
AAAA
CNAME
MX
NS
TXT
```

### Certificate Transparency

Les certificats publics sont utilisés pour identifier des hostnames et sous-domaines associés à la cible.

Source principale :

```text
crt.sh
```

### RDAP

OrgGraph récupère les informations publiques d'enregistrement disponibles via RDAP.

### HTTP

L'outil peut effectuer une requête HTTP passive sur les hôtes connus afin de récupérer notamment :

```text
HTTP status
page title
Server header
Content-Type
redirects
security headers
```

OrgGraph ne réalise pas de bruteforce de chemins ou de crawling massif.

---

## How it works

Chaque élément collecté est d'abord enregistré comme une **observation**.

Exemple :

```text
api.example.com
```

peut être observé indépendamment par :

```text
Certificate Transparency
DNS
HTTP
```

OrgGraph fusionne ensuite les observations correspondant à la même ressource afin de créer une entité unique.

```text
api.example.com

Evidence
├── Certificate Transparency
├── DNS
└── HTTP
```

Les relations entre entités peuvent ensuite être construites :

```text
example.com
     │
     └── HAS_SUBDOMAIN
              │
              ▼
       api.example.com
              │
              └── RESOLVES_TO
                       │
                       ▼
                  IP address
```

---

## Explainable scoring

OrgGraph utilise un système de score permettant d'indiquer la force des signaux associés à une entité ou une relation.

Exemple :

```text
Association confidence

90 / 100

Evidence

+35 target namespace
+25 DNS confirmation
+20 Certificate Transparency
+10 HTTP confirmation
```

Ce score est un **score de confiance interne et explicable**.

Il ne doit pas être interprété comme une probabilité scientifique.

La commande :

```bash
python3 orggraph.py explain ENTITY_ID
```

permet d'afficher les éléments ayant contribué au score.

---

## Installation

### Requirements

- Python 3.10+
- Linux/macOS recommandé

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/orggraph.git
cd orggraph
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the self-test:

```bash
python orggraph.py selftest
```

Sur Debian/Ubuntu, si la création du virtual environment échoue :

```bash
sudo apt install python3-venv
```

---

## Usage

### Scan a domain

```bash
python orggraph.py scan example.com
```

Example output:

```text
Target: example.com

Collectors
────────────────────────────────────

✓ DNS
✓ Certificate Transparency
✓ RDAP
✓ HTTP

Correlating observations...
Scoring relationships...
Saving scan...

────────────────────────────────────

Entities                     42
Relationships                67
New findings                 42

Scan ID: xxxxxxxx
```

---

## Commands

### Scan

```bash
python orggraph.py scan example.com
```

### Target summary

```bash
python orggraph.py show example.com
```

### List entities

```bash
python orggraph.py entities example.com
```

### Explain an entity or relationship

```bash
python orggraph.py explain ENTITY_ID
```

### Compare the two latest scans

```bash
python orggraph.py diff example.com
```

### Timeline

```bash
python orggraph.py timeline example.com
```

### Export

```bash
python orggraph.py export example.com
```

### Web UI

```bash
python orggraph.py ui
```

Then open:

```text
http://127.0.0.1:8765
```

### Self-test

```bash
python orggraph.py selftest
```

### Help

```bash
python orggraph.py --help
```

---

## Useful options

### Disable the banner

```bash
python orggraph.py scan example.com --no-banner
```

### JSON output

Useful for automation:

```bash
python orggraph.py scan example.com --json
```

### Verbose mode

```bash
python orggraph.py scan example.com --verbose
```

### Debug mode

```bash
python orggraph.py scan example.com --debug
```

### Select collectors

```bash
python orggraph.py scan example.com --collectors dns,http
```

### Filter entities

```bash
python orggraph.py entities example.com --type Subdomain --min-score 60
```

---

## Scan history

Every scan is stored locally.

Running:

```bash
python orggraph.py scan example.com
```

multiple times allows OrgGraph to compare observations over time.

Then:

```bash
python orggraph.py diff example.com
```

can show changes such as:

```text
NEW

+ api-v2.example.com


CHANGED

~ api.example.com
  IP changed


NOT OBSERVED

- old-api.example.com
```

`NOT OBSERVED` does **not** necessarily mean that the resource has been deleted.

It only means that OrgGraph did not observe it during the latest scan.

---

## Timeline

The timeline command reconstructs when entities were first or last observed.

```bash
python orggraph.py timeline example.com
```

Example:

```text
2026-09-01
│
├─ first seen: example.com
├─ first seen: api.example.com
│
2026-09-03
│
├─ api.example.com IP changed
│
2026-09-05
│
└─ first seen: dev.example.com
```

---

## Web interface

OrgGraph includes a local web interface.

Start it with:

```bash
python orggraph.py ui
```

Default address:

```text
http://127.0.0.1:8765
```

The interface provides access to:

- target overview
- entities
- relationships
- interactive graph
- scans
- timeline
- changes
- evidence and scores

The graph visualization uses Cytoscape.js loaded from a CDN.

---

## Local files

OrgGraph creates several files locally while it runs.

```text
orggraph.db
config.json
exports/
```

### `orggraph.db`

SQLite database containing scan history, observations, entities and relationships.

### `config.json`

Local configuration such as:

```text
timeouts
concurrency
user-agent
```

### `exports/`

Generated JSON exports.

These files are intentionally excluded from the Git repository.

A safe example configuration is provided as:

```text
config.example.json
```

---

## Repository structure

The project intentionally remains mostly single-file.

```text
orggraph/
│
├── orggraph.py
├── pyproject.toml
├── requirements.txt
├── config.example.json
├── README.md
└── .gitignore
```

Runtime files such as the database, exports, local configuration, build artifacts and virtual environments should not be committed.

---

## Passive by design

OrgGraph is designed as a passive OSINT and defensive intelligence tool.

It does **not** intentionally perform:

- port scanning
- credential attacks
- password bruteforce
- authentication bypass
- vulnerability exploitation
- aggressive endpoint enumeration
- private resource access
- intrusive network scanning

A failed source does not cause OrgGraph to fabricate results.

If a collector is unavailable or rate-limited, the scan continues with the remaining sources.

---

## Limitations

Public OSINT data can be:

- incomplete
- outdated
- temporarily unavailable
- misleading
- hosted on shared infrastructure

A relationship discovered by OrgGraph should therefore be treated as an analytical signal, not automatically as proof of ownership.

Certificate Transparency services such as `crt.sh` can also occasionally be slow or unavailable.

---

## Responsible use

Use OrgGraph only for legitimate OSINT, defensive security, research, asset discovery and systems for which you are authorized to perform reconnaissance.

The user is responsible for complying with applicable laws, service terms and authorization requirements.

---

## License

Add the license applicable to your project here.

For an open-source security tool, a common choice is:

```text
MIT License
```

but choose the license that matches how you want others to use and redistribute the project.

---

## Author

Created by **maxennce**

X / Twitter:

```text
https://x.com/maxennce
```