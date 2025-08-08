# 🕵️ APTHunter

**APTHunter** is a Python tool to query, filter, and visualize information about APT (Advanced Persistent Threat) groups using the public [MITRE ATT&CK](https://attack.mitre.org/) database.

It features a modern Streamlit web interface for quick searches by country, alias, or sector, displaying tactics, techniques, sectors, aliases, and official links, plus CSV export.

---

## 🚀 Main Features

- 🔎 Query and visualize APT groups from MITRE ATT&CK via `attackcti`.
- 🌍 Filter by country, alias, or sector.
- 🏷️ Shows aliases, tactics, techniques, sectors, description, and official link.
- 📊 Export filtered results to CSV with one click.
- ⚡ Modern web visualization with Streamlit.
- 📈 Interactive statistics for groups, techniques, malware, and sectors.
- 🦠 Browse documented malware, tools, and campaigns.
- 🛡️ Explore ATT&CK tactics and techniques with mitigations.
- 🎯 Group APTs by country.
- 🐍 Python-based, easy to understand and customize.

---

## 🖼️ Suggested Screenshots

> Add screenshots of the Streamlit interface and statistics tab for better visual presentation.

---

## 🗂️ Tabs & Functionality

- **🔍 APT Search:** Filter and explore groups by country, alias, or sector. Export results to CSV.
- **🛡️ Tactics & Techniques:** Browse all ATT&CK tactics and techniques, with details and mitigations.
- **🦠 Malware:** Browse documented malware, with description, platforms, and related techniques.
- **🛠️ Tools:** Explore tools used by groups, with details and related techniques.
- **🎯 Campaigns:** View attributed campaigns, period, targets, and description.
- **📊 Statistics:** Visualize charts and tables for groups by country, most used techniques, most frequent malware, and most targeted sectors.

---

## 📦 Requirements

Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## 🖥️ Quick Start

### 1. Run the web app

From the main folder:

```bash
streamlit run app.py
```

### 2. Search options

- **By country:** Select a country to see related groups.
- **By alias:** Enter part or all of the alias (e.g., `APT29`).
- **By sector:** Filter by sectors like energy, finance, government, health.

### 3. Visualization

Each group shows:

- 🎯 Name
- 🏷️ Aliases
- 🧩 Tactics
- 🛠️ Techniques
- 🏢 Sectors
- 🔗 MITRE ATT&CK link
- 📝 Description
- 🦠 Used malware
- 🎯 Attributed campaigns

### 4. Export results

Click the **Export results to CSV** button to download filtered data.

---

## 🛠️ Project Structure

```
apt_hunter.py
app.py
requirements.txt
apt_hunter/
	core.py
	filters.py
	output.py
data/
	choices.json
	enterprise-attack.json
```

---

## 🤝 Credits

- Based on [MITRE ATT&CK](https://attack.mitre.org/) and [attackcti](https://github.com/OTRF/ATTACK-Python-Client).
- Web interface with [Streamlit](https://streamlit.io/).

---

## 📄 License

This project is distributed under the MIT license. See the LICENSE file for details.
