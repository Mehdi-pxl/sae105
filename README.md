# SAÉ 1.05 - Network Log Analysis

## Project Context

Analysis of network logs from a France-India production site to identify anomalies causing network saturation.

## Project Structure

```
sae105/
├── data/                    # tcpdump log files
│   ├── DumpFile.txt
│   ├── DumpFile05.txt
│   └── fichier182.txt
├── scripts/
│   ├── analyse_reseau.py    # Main Python analysis script
│   └── vba.txt              # VBA macro for Excel
├── rapports/                # Generated reports (1 subfolder per file)
│   ├── DumpFile/
│   │   ├── rapport_*.csv
│   │   ├── rapport_*.json
│   │   └── rapport_*.md
│   └── DumpFile05/
├── web_interface/           # Symfony web dashboard
└── README.md
```

## Installation

### Requirements

- Python 3.8+
- Pandas library

### Install Dependencies

```bash
python -m pip install pandas
```

## Usage

### Analyze Default File

```bash
cd scripts
python analyse_reseau.py
```

### Analyze a Specific File

```bash
python analyse_reseau.py -f ../data/DumpFile05.txt
```

### Output

The script automatically creates a subfolder in `rapports/` named after the source file, containing 3 report files:

| Format | Description |
|--------|-------------|
| `.csv` | Full data export (Excel compatible, `;` separator) |
| `.json` | JSON format for web interface |
| `.md` | Readable report with tables and recommendations |

## Detected Anomalies

| Type | Description | Threshold |
|------|-------------|-----------|
| **SYN Flood** | Flooding attack with SYN packets | > 100 packets |
| **Port Scan** | Network reconnaissance (DNS queries) | > 10 ports scanned |

## Example Output

```
============================================================
     SAÉ 1.05 - NETWORK LOG ANALYSIS (TCPDUMP)
============================================================

[INFO] Reading file: ../data/DumpFile.txt
[INFO] 10931 valid lines parsed
[INFO] Analyzing anomalies...
[INFO] 2 anomaly(ies) detected

[OK] CSV report generated
[OK] JSON report generated
[OK] Markdown report generated

✅ 10931 packets analyzed
⚠️  2 anomaly(ies) detected
📁 Reports saved in: ../rapports/DumpFile/
```

## Web Interface (Optional)

```bash
cd web_interface
php -S localhost:8000 -t public
```

Access: http://localhost:8000

Features:
- Report history listing by source file
- Interactive charts (Attack Types & Traffic Timeline)
- Packet data table with flags highlighting
- PDF export via browser print

## Author

BUT R&T Student - January 2026
