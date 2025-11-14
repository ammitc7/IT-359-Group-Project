#  Video Presentation
> Video (Unlisted YouTube/Vimeo):* https://YOUR-VIDEO-LINK-HERE

# IT-359 Group Project — Automated Recon Output Parsing & Alerting (Educational)

 Project Purpose (The What)
This project demonstrates how basic networking tools (e.g., nmap, netcat, masscan) can be combined with simple scripts to **parse saved scan outputs**, normalize them into readable data, and **alert** when an **unexpected open port** appears. It is designed for **authorized, lab-only** use and focuses on **post-scan automation** and reporting.

> **Legal/Ethical**: Only scan networks you own or have **explicit written authorization** for. The default workflow is **parsing-only** and **dry-run**.

---

## ⚙️ Dependencies
- Python 3.10+
- See `requirements.txt` for Python libs

---

Setup 
```bash
git clone https://github.com/ammitc7/IT-359-Group-Project.git
cd IT-359-Group-Project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
 Usage (Quick Demo)
In Step 2 we will add the safe demo command that parses a sample nmap XML and writes a report (no live scanning).
Activate your virtual environment:
source .venv/bin/activate
Run the orchestrator (coming in Step 2).
View outputs in the output/ folder.
Testing
pytest -q
epository Structure 
your-project-name/
├── .gitignore
├── README.md
├── requirements.txt
├── src/
│   └── __init__.py
├── docs/
│   └── Final_Writeup_Template.md
└── tests/
Rubric Alignment Checklist
GitHub Repository (40 pts)
 Program runs and achieves goals (we’ll complete in Step 2–3)
 Repo structure is clean; code commented (in progress)
 README has setup, usage, dependencies, video link at top
Final Writeup (40 pts)
 Template included in docs/ (export to PDF)
 Fill in sections (Intro, How, Why, Conclusion) and add diagrams
Video (20 pts)
 10–15 min overview + demo
 Link at top of README (replace placeholder)
Authorization
See AUTHORIZATION.md for rules on safe, permitted use. Default behavior in our code will be dry-run and parsing-only.
