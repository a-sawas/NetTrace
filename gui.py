"""
gui.py
Stage 6: Tkinter GUI with NetworkX + Matplotlib graph visualization.

 Multi-path support:
  - _execute_pipeline() calls find_attack_paths() 
  - _draw_graph() draws EVERY attack path in red
  - _write_report() reports ALL paths with per-hop risk
  - Node coloring: every node that appears in ANY attack path is red

Node colors:
  Red    → attack path nodes (any path)
  Gold   → critical node (most pivotal intermediate)
  Orange → other suspicious nodes (high-risk but not on a path)
  Gray   → normal nodes
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import networkx as nx
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class NetTraceGUI:
    def __init__(self, root):
        self.root    = root
        self.root.title("NetTrace — AI-Powered Attack Path Reconstruction")
        self.root.geometry("1280x800")
        self.root.configure(bg="#1e1e2e")
        self.results = None
        self._build_ui()

    # ──────────────────────────────────────────────────────────────────────
    # UI construction
    # ──────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Title bar
        title_frame = tk.Frame(self.root, bg="#181825", pady=8)
        title_frame.pack(fill="x")
        tk.Label(
            title_frame, text="⬡  NetTrace",
            font=("Segoe UI", 18, "bold"), fg="#cba6f7", bg="#181825"
        ).pack(side="left", padx=20)
        tk.Label(
            title_frame, text="AI-Powered Network Attack Path Reconstruction",
            font=("Segoe UI", 11), fg="#a6adc8", bg="#181825"
        ).pack(side="left")

        # Control bar
        ctrl_frame = tk.Frame(self.root, bg="#1e1e2e", pady=8)
        ctrl_frame.pack(fill="x", padx=20)

        self.btn_demo = tk.Button(
            ctrl_frame, text="▶  Run Demo (no PCAP needed)",
            command=self._run_demo,
            font=("Segoe UI", 10, "bold"),
            bg="#a6e3a1", fg="#1e1e2e", relief="flat",
            padx=14, pady=6, cursor="hand2"
        )
        self.btn_demo.pack(side="left", padx=(0, 10))

        self.btn_pcap = tk.Button(
            ctrl_frame, text="📂  Load PCAP File",
            command=self._load_pcap,
            font=("Segoe UI", 10),
            bg="#89b4fa", fg="#1e1e2e", relief="flat",
            padx=14, pady=6, cursor="hand2"
        )
        self.btn_pcap.pack(side="left", padx=(0, 10))

        self.status_label = tk.Label(
            ctrl_frame, text="Ready. Run demo or load a PCAP file.",
            font=("Segoe UI", 9), fg="#a6adc8", bg="#1e1e2e"
        )
        self.status_label.pack(side="left", padx=10)

        # Main content: graph (left) + panel (right)
        content = tk.Frame(self.root, bg="#1e1e2e")
        content.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        graph_frame = tk.Frame(content, bg="#181825", relief="flat")
        graph_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))

        self.fig, self.ax = plt.subplots(figsize=(9, 6), facecolor="#181825")
        self.ax.set_facecolor("#181825")
        self.ax.axis("off")
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Right panel
        panel = tk.Frame(content, bg="#181825", width=340)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)

        tk.Label(
            panel, text="Analysis Report",
            font=("Segoe UI", 12, "bold"), fg="#cba6f7", bg="#181825"
        ).pack(pady=(12, 4), padx=10, anchor="w")

        self.report_box = scrolledtext.ScrolledText(
            panel, wrap="word", bg="#1e1e2e", fg="#cdd6f4",
            font=("Consolas", 9), relief="flat", padx=10, pady=10,
            insertbackground="#cdd6f4"
        )
        self.report_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        
        legend_frame = tk.Frame(panel, bg="#181825")
        legend_frame.pack(fill="x", padx=10, pady=(0, 12))
        for color, label in [
            ("#f38ba8", "Attack Path"),
            ("#f9e2af", "Critical Node"),
            ("#fab387", "Suspicious"),
            ("#9399b2", "Normal"),
        ]:
            row = tk.Frame(legend_frame, bg="#181825")
            row.pack(anchor="w")
            tk.Label(row, text="●", fg=color, bg="#181825",
                     font=("Segoe UI", 13)).pack(side="left")
            tk.Label(row, text=f"  {label}", fg="#a6adc8", bg="#181825",
                     font=("Segoe UI", 9)).pack(side="left")

    # ──────────────────────────────────────────────────────────────────────
    # Pipeline orchestration
    # ──────────────────────────────────────────────────────────────────────

    def _set_status(self, msg):
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def _run_demo(self):
        self._set_status("Running demo pipeline...")
        self.btn_demo.config(state="disabled")
        self.btn_pcap.config(state="disabled")
        t = threading.Thread(target=self._execute_pipeline, args=(None,), daemon=True)
        t.start()

    def _load_pcap(self):
        filepath = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if not filepath:
            return
        self._set_status(f"Loaded: {filepath}")
        self.btn_demo.config(state="disabled")
        self.btn_pcap.config(state="disabled")
        t = threading.Thread(target=self._execute_pipeline, args=(filepath,), daemon=True)
        t.start()

    def _execute_pipeline(self, pcap_path):
        try:
            from pcap_parser   import parse_pcap, generate_demo_connections
            from ai_classifier import classify_connections, classify_demo
            from graph_builder import build_graph, get_adjacency_for_display
            from dijkstra      import find_attack_paths          # ← NEW multi-path API
            from greedy        import find_critical_node, get_suspicious_nodes

            self._set_status("Stage 1/5 — Parsing PCAP...")
            if pcap_path:
                connections = parse_pcap(pcap_path)
                if not connections:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Error", "No connections found in PCAP file."))
                    return
            else:
                connections = generate_demo_connections()

            self._set_status("Stage 2/5 — AI classifying connections...")
            connections = classify_connections(connections) if pcap_path else classify_demo(connections)

            self._set_status("Stage 3/5 — Building graph...")
            graph, nodes = build_graph(connections)
            edges        = get_adjacency_for_display(connections)

            self._set_status("Stage 4/5 — Running Dijkstra (multi-path)...")
            all_paths, all_edges, source, targets = find_attack_paths(graph, connections)

            # Build a flat set of all nodes that appear in ANY attack path
            attack_set = {node for path in all_paths for node in path}

            self._set_status("Stage 5/5 — Finding critical node...")
            critical_node, scores = find_critical_node(all_paths, connections)
            suspicious            = get_suspicious_nodes(connections, all_paths)

            self.results = {
                "connections":  connections,
                "nodes":        nodes,
                "edges":        edges,
                "all_paths":    all_paths,       # list of paths
                "all_edges":    all_edges,        # list of edge-lists
                "attack_set":   attack_set,       # flat set of all red nodes
                "source":       source,
                "targets":      targets,
                "critical_node": critical_node,
                "suspicious":   suspicious,
            }

            self.root.after(0, self._render_results)

        except Exception as e:
            import traceback
            self.root.after(0, lambda: messagebox.showerror("Pipeline Error", str(e)))
            traceback.print_exc()
        finally:
            self.root.after(0, lambda: self.btn_demo.config(state="normal"))
            self.root.after(0, lambda: self.btn_pcap.config(state="normal"))

   
    # Rendering
    

    def _render_results(self):
        self._draw_graph(self.results)
        self._write_report(self.results)
        self._set_status("✓ Analysis complete.")

    def _draw_graph(self, r):
        self.ax.clear()
        self.ax.set_facecolor("#181825")
        self.ax.axis("off")

        G = nx.DiGraph()
        for (src, dst, weight, risk, label) in r["edges"]:
            G.add_edge(src, dst, weight=weight, risk=risk, label=label)

        attack_set    = r["attack_set"]
        critical_node = r["critical_node"]

        # ── Node colours ──────────────────────────────────────────────────
        node_colors = []
        for node in G.nodes():
            if node == critical_node:
                node_colors.append("#f9e2af")   # gold
            elif node in attack_set:
                node_colors.append("#f38ba8")   # red — on ANY attack path
            elif node in r["suspicious"]:
                node_colors.append("#fab387")   # orange
            else:
                node_colors.append("#9399b2")   # grey

        pos = nx.spring_layout(G, seed=42, k=2.5)

        # ── Background edges (grey) ───────────────────────────────────────
        nx.draw_networkx_edges(
            G, pos, ax=self.ax,
            edge_color="#45475a", arrows=True,
            arrowsize=15, width=1.0,
            connectionstyle="arc3,rad=0.1"
        )

        # ── Attack-path edges — draw EVERY path in red ────────────────────
        all_attack_edges = set()
        for path in r["all_paths"]:
            for u, v in zip(path[:-1], path[1:]):
                all_attack_edges.add((u, v))

        attack_edges_in_G = [(u, v) for (u, v) in all_attack_edges if G.has_edge(u, v)]
        if attack_edges_in_G:
            nx.draw_networkx_edges(
                G, pos, edgelist=attack_edges_in_G, ax=self.ax,
                edge_color="#f38ba8", arrows=True,
                arrowsize=20, width=2.5,
                connectionstyle="arc3,rad=0.1"
            )

        # ── Nodes ─────────────────────────────────────────────────────────
        nx.draw_networkx_nodes(
            G, pos, ax=self.ax,
            node_color=node_colors, node_size=800,
            linewidths=1.5, edgecolors="#cdd6f4"
        )

        short_labels = {n: n.split(".")[-1] if "." in n else n for n in G.nodes()}
        nx.draw_networkx_labels(
            G, pos, labels=short_labels, ax=self.ax,
            font_color="#1e1e2e", font_size=8, font_weight="bold"
        )

        self.fig.tight_layout()
        self.canvas.draw()

    def _write_report(self, r):
        self.report_box.config(state="normal")
        self.report_box.delete("1.0", "end")

        lines = []
        lines.append("=" * 38)
        lines.append("  NETTRACE ANALYSIS REPORT")
        lines.append("=" * 38)
        lines.append("")

        all_paths  = r["all_paths"]
        all_edges  = r["all_edges"]
        targets    = r["targets"]

        if all_paths:
            lines.append(f"ATTACKER:  {r['source']}")
            lines.append(f"VICTIMS:   {len(targets)} identified")
            lines.append("")

            for path_idx, (path, path_edges) in enumerate(zip(all_paths, all_edges)):
                lines.append(f"── PATH {path_idx + 1} ──────────────────────")
                lines.append(f"  {path[0]}  (attacker)")
                for node in path[1:]:
                    tag = ""
                    if node == r["critical_node"]:
                        tag = "  ← CRITICAL"
                    elif node == path[-1]:
                        tag = "  ← TARGET"
                    lines.append(f"  ↓ {node}{tag}")
                lines.append("")

                if path_edges:
                    lines.append("  RISK PER HOP:")
                    for i, edge in enumerate(path_edges):
                        if i + 1 < len(path):
                            src_short = path[i].split(".")[-1]
                            dst_short = path[i + 1].split(".")[-1]
                            risk      = edge.get("risk_score", 0)
                            label     = edge.get("label", "")
                            lines.append(f"  .{src_short}→.{dst_short}  {risk:3d}/100")
                            lines.append(f"           {label}")
                    lines.append("")

                    avg_risk = sum(e.get("risk_score", 0) for e in path_edges) // len(path_edges)

                    lines.append(f"  PATH RISK: {avg_risk}/100")
                    lines.append("")
        else:
            lines.append("No attack path found.")
            lines.append("")

        if r["critical_node"]:
            lines.append(f"CRITICAL NODE:")
            lines.append(f"  {r['critical_node']}")
            lines.append(f"  Blocking this node disrupts")
            lines.append(f"  all paths passing through it.")
        else:
            lines.append("No critical node identified.")

        lines.append("")
        lines.append("=" * 38)
        lines.append(f"  Total connections: {len(r['connections'])}")
        lines.append(f"  Total IPs:         {len(r['nodes'])}")
        lines.append(f"  Attack paths:      {len(all_paths)}")
        lines.append("=" * 38)

        self.report_box.insert("end", "\n".join(lines))
        self.report_box.config(state="disabled")