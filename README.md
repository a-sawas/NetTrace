# NetTrace — AI-Powered Network Attack Path Reconstruction


---

## What is NetTrace?

NetTrace is a forensic analysis tool that takes a raw network capture (.pcap) file,
uses AI to classify each connection and assign a risk score, then runs Dijkstra's
algorithm to reconstruct the exact attack path through the network. It also identifies
the single most critical node that, if blocked, would disrupt all attack routes.

---

## How it Works

1. **pcap_parser.py** — Reads the .pcap file and extracts network flows (IPv4 + IPv6)
2. **ai_classifier.py** — Sends flows to Google Gemini API for risk scoring (0–100)
3. **graph_builder.py** — Builds a weighted directed graph from the risk scores
4. **dijkstra.py** — Runs custom min-heap Dijkstra to find all high-risk attack paths
5. **greedy.py** — Identifies the critical node using a Greedy algorithm
6. **gui.py** — Displays the interactive graph and analysis report

---

## Installation & Setup

### 1. Download the Project
1. Go to the top of this GitHub page and click the green **`<> Code`** button.
2. Select **Download ZIP** from the dropdown menu.
3. Once downloaded, right-click the `.zip` file and extract/unzip the folder to your computer.

### 2. Open in Visual Studio Code
1. Launch Visual Studio Code (VS Code).
2. Go to **File → Open Folder** and select the `NetTrace` folder you just extracted.

### 3. Install Dependencies
Open the integrated terminal inside VS Code (you can press ``Ctrl` + ` ` ``) and run the following command:
```bash
pip install scapy networkx matplotlib requests google-genai

---

## How to Run

```bash
python main.py
```

1. Click **"Run Demo"** — no PCAP file or API key needed, runs instantly
2. To test with a real PCAP:
   - Add your Gemini API key in `ai_classifier.py`
   - Click **"Load PCAP File"** and select any .pcap file

---

## Algorithms Used

- **Dijkstra's Algorithm** (custom min-heap) — O((V+E) log V)
- **Greedy Critical Node Selection** — O(P × N)

---

## AI Integration

Google Gemini classifies raw network connections and assigns risk scores.
The classical algorithms handle all core logic using those scores.
