"""
Generate a clean, professional, readable PDF containing all source codes
of the QI-CTD Project for Smart India Hackathon 2026.
"""

import os
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Preformatted, PageBreak, Table, TableStyle, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return  # Suppress headers/footers on title page
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Header
        self.drawString(54, 750, "QI-CTD — Quantum-Inspired Cyber Threat Detection | Team Qubit Defenders (T-YMK16)")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)

        # Footer
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Smart India Hackathon 2026 — Problem Statement ID: SIH26141")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_text)
        self.restoreState()


def create_code_pdf(output_pdf_path="QI_CTD_All_Source_Code.pdf"):
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=60,
        bottomMargin=60
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        alignment=1
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        alignment=1
    )

    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
        alignment=1
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=12,
        spaceAfter=4
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=6,
        spaceAfter=3
    )

    desc_style = ParagraphStyle(
        'FileDesc',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#475569"),
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # ==================== COVER PAGE ====================
    story.append(Spacer(1, 30))
    story.append(Paragraph("SMART INDIA HACKATHON 2026", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("QI-CTD: Quantum-Inspired Cyber Threat Detection", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Complete Technical Source Code & System Implementation", subtitle_style))
    story.append(Spacer(1, 20))

    meta_box = [
        [Paragraph("<b>Team Name:</b>", styles['Normal']), Paragraph("Qubit Defenders", styles['Normal'])],
        [Paragraph("<b>Team ID:</b>", styles['Normal']), Paragraph("T-YMK16", styles['Normal'])],
        [Paragraph("<b>Problem Statement ID:</b>", styles['Normal']), Paragraph("SIH26141", styles['Normal'])],
        [Paragraph("<b>Problem Statement Title:</b>", styles['Normal']), Paragraph("Quantum-Inspired Cyber Threat Detection for Digital-Signature Verification", styles['Normal'])],
        [Paragraph("<b>Theme:</b>", styles['Normal']), Paragraph("Blockchain & Cybersecurity", styles['Normal'])],
        [Paragraph("<b>Category:</b>", styles['Normal']), Paragraph("Software", styles['Normal'])],
        [Paragraph("<b>Repository:</b>", styles['Normal']), Paragraph("https://github.com/Rajdeep13-blip/qi-ctd", styles['Normal'])],
        [Paragraph("<b>Live Cloud Deployment:</b>", styles['Normal']), Paragraph("https://qi-ctd.onrender.com", styles['Normal'])],
    ]
    t = Table(meta_box, colWidths=[140, 360])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    exec_summary = (
        "<b>Project Abstract:</b><br/>"
        "QI-CTD is a quantum-inspired security platform engineered to detect compromised cryptographic signatures, "
        "ECDSA nonce collisions, and 'Harvest Now, Decrypt Later' (HNDL) attacks in 3.8 milliseconds without reading private keys. "
        "It integrates QUBO Simulated Annealing, MPS Tensor Networks (chi=4), and Grover Amplitude Amplification with "
        "Automated SOAR lockdown and NIST FIPS 204 (ML-DSA / Dilithium) Post-Quantum Cryptography seals."
    )
    story.append(Paragraph(exec_summary, meta_style))
    story.append(PageBreak())

    # ==================== SOURCE CODE FILES ====================
    base_dir = os.path.dirname(os.path.abspath(__file__))

    code_files = [
        ("core/qubo_engine.py", "1. Core Algorithm 1 — QUBO Simulated Annealing Outlier Solver", 
         "Formulates signature outlier detection as a Hamiltonian energy minimization problem to isolate anomalous signatures."),
        
        ("core/tensor_network.py", "2. Core Algorithm 2 — MPS Tensor Network Correlation Classifier", 
         "Matrix Product State (MPS) tensor train with chi=4 bond dimension; captures non-linear cross-feature entanglement in linear time."),
        
        ("core/grover_search.py", "3. Core Algorithm 3 — Grover Amplitude Amplification Nonce Search", 
         "Simulates Grover diffusion operator for quadratic speedup in detecting cross-IP ECDSA nonce collision reuse."),
        
        ("core/qvs_engine.py", "4. Core Algorithm 4 — Quantum Vulnerability Scoring (QVS) Engine", 
         "Computes 0-100 quantum vulnerability scores based on Mosca's Theorem (X + Y > Z) and recommends NIST PQC targets."),

        ("core/ecdsa_recovery.py", "5. Mathematical ECDSA Nonce Collision & Private Key Recovery Engine",
         "Pure Python secp256k1 elliptic curve engine deriving ephemeral nonce k and private key dA with exact algebraic proof."),

        ("core/doc_verifier.py", "6. Citizen Visual Document Verifier & CCA India Trust Registry",
         "Digital document verification engine supporting Aadhaar eSign, GeM e-Tender, DigiLocker degrees, side-by-side tamper diffs, timeline, and 6 Indian languages."),

        ("core/pqc_mldsa.py", "7. NIST FIPS 204 (ML-DSA-65 / Dilithium) Lattice Cryptographic Engine",
         "Post-quantum module-lattice cryptographic engine providing keypair generation, digital signing, and PEM seal verification."),

        ("telemetry/sniffer.py", "8. Zero-Key Non-Invasive Network Packet Sniffer",
         "Zero-key packet capture engine analyzing packet headers, Shannon entropy, byte distributions, and timing without reading secret keys."),
        
        ("telemetry/schema.py", "9. Telemetry & Schema Models", 
         "Data structures for RFC-5280 metadata, normalized signature telemetry, quantum risk assets, and SOAR alerts."),
        
        ("telemetry/normalizer.py", "10. Zero-Key Telemetry Normalizer", 
         "Extracts Shannon entropy, byte distributions, timing, and public metadata with zero plaintext / private key access."),
        
        ("telemetry/public_apis_ingestor.py", "11. Real Public APIs Telemetry Ingestor", 
         "Connects live to open APIs (Blockchain.info, crt.sh, CISA KEV) indexed in public-apis/public-apis catalog."),
        
        ("simulation/attack_generator.py", "12. Dynamic Cyber Attack Scenario Generator", 
         "Simulates 4 dynamic cyber attack vectors: ECDSA Nonce Reuse, Signature Malleability, Rogue CI/CD Signing, and Quantum HNDL."),
        
        ("database/db.py", "13. SQLite Audit Ledger & Database Layer", 
         "Persistent SQLite storage for telemetry events, cryptographic SOAR audit trails, and key status records."),
        
        ("engine.py", "14. Master QI-CTD Orchestration Engine", 
         "End-to-end orchestration pipeline tying telemetry normalizer, quantum engines, QVS risk scorer, MLDSA65 PQC, and SOAR mitigation."),
        
        ("api/server.py", "15. Multi-Threaded Public REST API Server", 
         "HTTP server binding to 0.0.0.0:8000 handling REST endpoints (/alerts, /soar/execute, /benchmarks, /metrics/live, /pqc/sign, /public-apis, /doc/verify)."),

        ("benchmarks/run_benchmarks.py", "16. Automated 1,000-Event Benchmark & Profiling Suite",
         "Evaluates detection recall, precision, latency percentiles (p50/p95/p99), and throughput across 1,000+ synthesized & real events."),

        ("dashboard/app.js", "17. Frontend Dashboard State Machine & SOAR Controller", 
         "Client-side JavaScript controller managing real-time canvas visualizers, citizen document verification, batch hub, and 1-Click Lockdown."),

        ("dashboard/index.html", "18. Frontend Dashboard UI Markup & Canvases", 
         "HTML5 markup for Citizen Verifier, Batch Hub, Integrations, SOC Triage, Quantum AI Core, Public APIs catalog, CISO Posture, and Benchmark Lab."),

        ("dashboard/styles.css", "19. Responsive Cyberpunk & Citizen Styling Theme",
         "Modern CSS stylesheet with dual-theme accents, glowing indicators, diff viewers, and smartphone WhatsApp simulator."),

        ("launch_desktop_app.py", "20. Desktop GUI & Offline Application Launcher", 
         "Tkinter-based desktop GUI launcher providing 1-click startup, cloud link, and local server process management."),

        ("run_demo.py", "21. Terminal Interactive Demo & Benchmark Script", 
         "Standalone terminal script demonstrating 3.8ms anomaly detection, ECDSA key recovery, and quantum vulnerability scoring.")
    ]

    for rel_path, section_title, description in code_files:
        full_path = os.path.join(base_dir, rel_path)
        if not os.path.exists(full_path):
            continue

        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code_text = f.read()

        story.append(Paragraph(section_title, h1_style))
        story.append(Paragraph(f"<b>File:</b> <code>{rel_path}</code>", h2_style))
        story.append(Paragraph(description, desc_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

        # Split into readable preformatted chunk that flows naturally across pages
        clean_lines = []
        for line in code_text.splitlines():
            if len(line) > 105:
                clean_lines.append(line[:105] + "...")
            else:
                clean_lines.append(line)
        clean_code = "\n".join(clean_lines)

        code_flowable = Preformatted(clean_code, code_style)
        story.append(code_flowable)
        story.append(Spacer(1, 14))
        story.append(PageBreak())

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[SUCCESS] PDF successfully generated at: {output_pdf_path}")

if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "QI_CTD_All_Source_Code.pdf"
    create_code_pdf(out_path)
