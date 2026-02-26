# Meta-Code Engine

A Python semantic code analyzer with Flask web interface.

## Quick Start

### Clone the repository
```bash
git clone https://github.com/KnottNefarious/meta-code-engine.git
cd meta-code-engine
```

### Install Flask
```bash
pip install flask
```

### Run the application
```bash
python app.py
```

### Access the analyzer
- **Computer**: Visit `http://localhost:5000`
- **Phone (same WiFi)**: Visit `http://YOUR_IP_ADDRESS:5000`

## Finding Your IP Address

**Windows:**
1. Open Command Prompt
2. Type: `ipconfig`
3. Look for "IPv4 Address" (example: 192.168.1.100)

**Mac/Linux:**
1. Open Terminal
2. Type: `ifconfig`
3. Look for "inet" (example: 192.168.1.100)

## Features

- ✨ Real-time code analysis
- ✨ Detects unused variables
- ✨ Finds unreachable code
- ✨ Mobile-friendly interface
- ✨ Works on any device with a browser

## How to Use

1. Paste Python code into the text area
2. Click the "Analyze" button
3. Get instant semantic analysis results

Results display:
- **Clean** - No issues found
- **Issues** - List of problems detected
- **Error** - Invalid Python syntax

## Project Structure

- `app.py` - Flask web server
- `templates/index.html` - Web interface
- `meta_code/dissonance.py` - Code analyzer
- `requirements.txt` - Python dependencies