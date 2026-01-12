# Network Security Monitoring - SAE 1.05

## Project Context

This project analyzes network logs from a France-India production site to identify security anomalies causing network saturation. The analysis focuses on detecting two main types of suspicious activities.

## Installation

### Requirements

- Python 3.8 or higher
- PHP 8.1 or higher
- Composer
- Symfony CLI

### Setup

1. Install Symfony dependencies:

```bash
cd sae-monitoring
composer install
```

## Usage

### Running the Analysis

To analyze the default log file:

```bash
python analyse_reseau.py
```

To analyze a specific file:

```bash
python analyse_reseau.py path/to/logfile.txt
```

The script generates two files in `sae-monitoring/public/rapports/`:
- A CSV file with detailed alert data
- A JSON file with a summary of findings

Each analysis creates timestamped files (format: rapport_YYYYMMDD_HHMMSS) to maintain a history of all analyses.

### Viewing Results

Start the Symfony web server:

```bash
cd sae-monitoring
symfony serve
```

Open your browser to http://localhost:8000

The web interface provides:
- A list of all generated reports
- Detailed views with interactive charts
- PDF export functionality via browser print

## Detected Anomalies

### SYN Flood Attack

Source IP: 190-0-175-100.gba.solunet.com.ar
Packets sent: 1969 SYN packets
Severity: CRITICAL
Additional info: Suspicious "XXXX" payload detected

### Abnormal Connection Timing

Multiple connections detected outside normal business hours (8h-18h), indicating potential unauthorized access attempts.

## Project Structure

```
sae105dydou/
├── analyse_reseau.py
├── 2025-SAE-main/
│   └── DumpFile.txt
├── sae-monitoring/
│   ├── src/Controller/
│   │   └── RapportController.php
│   ├── templates/rapport/
│   │   ├── index.html.twig
│   │   └── detail.html.twig
│   └── public/rapports/
└── README.md
```

## Technical Implementation

### Python Analysis Script

The script uses Python's standard library to:
- Parse tcpdump format logs with regular expressions
- Count SYN packets per source IP
- Detect connections outside normal hours
- Export results in CSV and JSON formats

Detection thresholds:
- SYN flood: more than 100 SYN packets from a single IP
- Normal hours: 8h-18h (India timezone)

### Symfony Web Interface

Single controller architecture using basic PHP functions:
- scandir() to list report files
- fopen() and fgetcsv() to read CSV data
- json_decode() to parse JSON summaries

### Data Visualization

Charts are generated using Chart.js loaded from CDN. Two chart types:
- Pie chart showing alert distribution by severity
- Bar chart showing attack type distribution

### PDF Export

The print functionality uses the browser's native print dialog with CSS media queries to hide navigation elements when printing.

## Security Recommendations

Based on the detected anomaly:

1. Block the attacking IP address immediately
2. Implement SYN cookies on affected servers
3. Deploy an intrusion detection system
4. Set up automated monitoring for similar patterns

## Technical Choices

### Why Chart.js via CDN

Using a CDN provides a simple integration without requiring local installation or build processes. The library is lightweight and well-documented.

### Why Browser Print for PDF

The native browser print function works across all platforms without requiring additional PHP libraries. Users can save as PDF directly from the print dialog.

### Why Timestamped Reports

Each analysis creates uniquely named files, preserving a complete history of network incidents. This allows for temporal analysis and prevents data loss from overwrites.

## Author

First year BUT R&T student
