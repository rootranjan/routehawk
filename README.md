```
                                  /^^^\                            
                                 / o o \                           
                                 \  v  /                            
                                  \ - /                             
                                   \|/                              
                                 __/|\__                           
                                /       \                          
                               /_________\                         

                               🦅 RouteHawk 🦅                         
                         API Attack Surface Discovery               
                     Developed by Ranjan Kumar (@rootranjan)                   
```

# 🦅 RouteHawk - AI-Powered API Attack Surface Discovery

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Framework Support](https://img.shields.io/badge/frameworks-10+-green.svg)](#supported-frameworks)

> **Discover, analyze, and secure your API attack surface across modern microservice architectures**

Developed by **[@rootranjan](https://github.com/rootranjan)** 

---

## 🎯 **The Problem We Solve**

### 💥 **Enterprise API Discovery Challenges**

Modern applications face critical security blind spots:

| **Pain Point** | **Real Impact** | **RouteHawk Solution** |
|----------------|-----------------|------------------------|
| **🔍 Hidden APIs** | 73% of organizations can't inventory their APIs | **Automated discovery** across codebases |
| **🚨 Security Gaps** | Unknown endpoints = unprotected attack surface | **Risk scoring** with AI analysis |
| **⚡ Microservice Sprawl** | 100+ services, 1000+ endpoints to track | **Multi-framework detection** in one scan |
| **🔄 Deployment Drift** | APIs change faster than security reviews | **Git comparison** and change tracking |
| **👥 Developer Blind Spots** | Security isn't visible during development | **IDE integration** and real-time feedback |

### 🎯 **What RouteHawk Does**

**RouteHawk is an AI-powered attack surface discovery tool** that automatically finds, analyzes, and risk-scores API endpoints across your entire codebase - helping security teams and developers proactively secure their APIs before they become vulnerabilities.

---

## 🚀 **Key Features**

### 🔍 **Multi-Framework API Discovery**
- **10+ Framework Support**: NestJS, Express, FastAPI, Spring Boot, Go, Django, Flask, NextJS, Ruby Rails, Laravel
- **Smart Pattern Matching**: Regex-based detection with framework-specific optimizations
- **Template Resolution**: Resolves dynamic routes and environment variables

### 🧠 **AI-Powered Analysis** 
- **Gemini Integration**: Advanced semantic analysis of route security
- **Risk Scoring**: Automated vulnerability assessment (0-100 scale)
- **Security Insights**: CWE mapping and remediation recommendations

### 📊 **Enterprise-Grade Reporting**
- **Multiple Formats**: JSON, HTML, CSV, SARIF for security tools
- **Rich Dashboards**: Interactive reports with risk breakdowns
- **Compliance Ready**: Enterprise security reporting standards

### 🔄 **Change Tracking & Comparison**
- **Git Integration**: Compare API changes between branches/tags/releases
- **Directory Comparison**: Analyze differences between deployments
- **Risk Impact Analysis**: Assess security implications of route changes

### ⚡ **Performance Optimized**
- **Intelligent Caching**: Faster re-scans with smart cache management
- **Parallel Processing**: Multi-threaded scanning for large codebases
- **Memory Efficient**: Optimized for enterprise-scale repositories

---

## 📦 **Quick Installation**

### **Prerequisites**
- Python 3.8+ 
- Git (for comparison features)

### **Install RouteHawk**

```bash
# 1. Clone the repository
git clone https://github.com/rootranjan/routehawk.git
cd routehawk

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install RouteHawk
pip install -e .

# 4. Verify installation
python routehawk.py --help
```

---

## 🛠️ **Usage Guide**

### **Basic Scanning**

```bash
# Scan a repository with auto-detection
python routehawk.py --repo-path /path/to/your/project

# Scan specific frameworks
python routehawk.py --repo-path /path/to/your/project --frameworks nestjs,express

# Generate multiple output formats
python routehawk.py --repo-path /path/to/your/project --output-format json,html,csv
```

### **Advanced Features**

```bash
# AI-powered analysis with risk assessment
python routehawk.py \
  --repo-path /path/to/your/project \
  --use-ai \
  --risk-threshold high \
  --output-format html

# Compare API changes between git tags
python routehawk.py \
  --repo-path /path/to/your/project \
  --compare-tags "v1.0.0,v2.0.0" \
  --output-format json

# Directory comparison for deployment analysis  
python routehawk.py \
  --repo-path /path/to/current/deployment \
  --compare-dir /path/to/previous/deployment \
  --include-file-changes
```

### **Web Interface**

```bash
# Start web-based interface
python web_cli_bridge.py

# Access dashboard at http://localhost:8182
```

---

## ⚙️ **Configuration**

### **Environment Variables**

Create `.env` file for optional features:

```bash
# AI Analysis (Optional)
GEMINI_API_KEY=your_gemini_api_key_here

# GitLab Integration (Optional) 
GITLAB_TOKEN=your_gitlab_token_here
GITLAB_URL=https://gitlab.com

# Web Interface
FLASK_ENV=development
SECRET_KEY=your_secret_key_here
```

### **Framework Configuration**

```bash
# Auto-detect frameworks (default)
--frameworks auto

# Specify frameworks explicitly
--frameworks nestjs,express,fastapi,go

# Scan all supported frameworks
--frameworks all
```

### **Output Configuration**

```bash
# Terminal output (default)
--output-format terminal

# Multiple formats
--output-format json,html,csv,sarif

# Custom output directory
--output-dir ./security-reports
```

### **Performance Tuning**

```bash
# Memory optimization for large repos
--performance-mode memory-optimized --max-memory 2048

# Fast scanning mode
--performance-mode fast --max-workers 8

# Enable intelligent caching
--cache-enabled --cache-cleanup 7
```

---

## 🔧 **Supported Frameworks**

| Framework | Language | Detection Features | Template Support |
|-----------|----------|-------------------|------------------|
| **NestJS** | TypeScript/JavaScript | Controllers, Decorators, Guards | ✅ Variables & Enums |
| **Express** | JavaScript | Routes, Middleware, Routers | ✅ Template Literals |
| **FastAPI** | Python | Path Operations, Dependencies | ✅ Path Parameters |
| **Spring Boot** | Java | Controllers, REST Mappings | ✅ Path Variables |
| **Go HTTP** | Go | Handlers, Mux Routers | ✅ Route Patterns |
| **Django** | Python | URLs, Views, Class-Based Views | ✅ URL Patterns |
| **Flask** | Python | Routes, Blueprints | ✅ Variable Rules |
| **NextJS** | TypeScript/JavaScript | API Routes, App Router | ✅ Dynamic Routes |
| **Ruby Rails** | Ruby | Routes, Controllers | ✅ RESTful Routes |
| **Laravel** | PHP | Routes, Controllers | ✅ Route Parameters |

---

## 📊 **Example Output**

### **Terminal Report**
```
🦅 RouteHawk Attack Surface Discovery Complete!

┌─────────────────────┬─────────┐
│ Metric              │ Count   │
├─────────────────────┼─────────┤
│ Total Routes        │ 1,247   │
│ High Risk Routes    │ 23      │
│ Medium Risk Routes  │ 156     │
│ Low Risk Routes     │ 1,068   │
│ Services Found      │ 12      │
│ Frameworks Detected │ 4       │
│ Scan Duration       │ 3.2s    │
└─────────────────────┴─────────┘

🚨 High Risk Routes:
• DELETE /admin/users/:id (Unauthenticated admin endpoint)
• POST /api/exec (Command execution endpoint)
• GET /debug/env (Environment disclosure)
```

### **JSON Output Sample**
```json
{
  "scan_id": "hawk_20240120_143022",
  "total_routes": 1247,
  "high_risk_routes": 23,
  "frameworks_detected": ["nestjs", "express", "fastapi"],
  "routes": [
    {
      "path": "/api/v1/users/:id",
      "method": "GET",
      "framework": "express",
      "authenticated": true,
      "risk_score": 25.5,
      "security_findings": []
    }
  ]
}
```

---

## 🤝 **Contributing**

### **Development Setup**

```bash
# Clone for development
git clone https://github.com/rootranjan/routehawk.git
cd routehawk

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/

# Code formatting
black routehawk/
flake8 routehawk/
```

### **Contribution Guidelines**

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### **Adding Framework Support**

See `detectors/base_detector.py` for implementing new framework detectors.

---

## 📋 **Roadmap**

- [ ] **GitHub Actions Integration** - CI/CD security scanning
- [ ] **VS Code Extension** - Real-time API discovery in IDE
- [ ] **Kubernetes Integration** - Runtime API discovery
- [ ] **GraphQL Support** - Schema and resolver analysis
- [ ] **API Spec Generation** - OpenAPI/Swagger auto-generation
- [ ] **Cloud Provider Integration** - AWS API Gateway, Azure APIM
- [ ] **Machine Learning Models** - Custom vulnerability detection

---

## 📜 **License**

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

### **What this means:**
- ✅ **Free for non-commercial use** - Open source, research, education
- ✅ **Modification allowed** - Fork, modify, improve
- ✅ **Distribution allowed** - Share with others
- ⚠️  **Commercial use restrictions** - Contact for commercial licensing
- 📋 **Source code disclosure required** - Any modifications must be open source

### **Commercial Licensing**
For commercial use, enterprise support, or proprietary integrations, please contact:
- **📧 Email**: rootranjan+routehawk@gmail.com
- **💬 GitHub**: [@rootranjan](https://github.com/rootranjan)

---

## 👨‍💻 **Author & Maintainer**

**Ranjan Kumar** ([@rootranjan](https://github.com/rootranjan))
- 🛠️ **Creator & Lead Developer** of RouteHawk
- 🔒 **Security Engineer** specializing in product security
- 📧 **Email**: rootranjan+routehawk@gmail.com
- 💬 **GitHub**: [Create an issue](https://github.com/rootranjan/routehawk/issues) for support

---

## 🙏 **Acknowledgments**

- **Security Community** - For continuous feedback and vulnerability research
- **Open Source Contributors** - Making RouteHawk better every day
- **Framework Developers** - For creating amazing web frameworks to secure

---

## 🚨 **Security Disclosure**

Found a security vulnerability in RouteHawk? Please report it privately to [@rootranjan](https://github.com/rootranjan) before public disclosure.

---

## ⭐ **Star History**

If RouteHawk helped secure your APIs, please ⭐ **star this repository** to support the project!

[![Star History Chart](https://api.star-history.com/svg?repos=rootranjan/routehawk&type=Date)](https://star-history.com/#rootranjan/routehawk&Date)

---

**Made with ❤️ by [@rootranjan](https://github.com/rootranjan) | Securing APIs, one route at a time 🦅** 