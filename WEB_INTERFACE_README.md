# Deobfuscator - Web Interface

A modern, responsive Flask web application for detecting obfuscated binaries. Upload executable files and get detailed analysis including entropy calculation, XOR detection, and suspicious API identification.

## Features

### 🎯 **Binary Analysis**
- **Entropy Analysis**: Shannon entropy calculation for each section and overall file
- **Section Properties**: Detailed PE section information (virtual size, raw size, permissions)
- **Import Analysis**: Lists all imported DLLs and functions, highlights suspicious APIs
- **XOR Detection**: Identifies potential XOR-encoded strings and keys
- **Obfuscation Scoring**: Automatic risk assessment with visual scoring

### 🖥️ **User Interface**
- Modern Bootstrap 5 responsive design
- Drag-and-drop file upload
- Real-time analysis progress
- Tabbed detailed results view
- Color-coded severity indicators
- Mobile-friendly interface

### 🔒 **Security**
- File upload validation (type and size)
- Secure filename handling
- Temporary file cleanup
- 50MB file size limit

## Installation

### Prerequisites
- Python 3.6+
- pip package manager
- Virtual environment (recommended)

### Setup

1. **Clone/Navigate to Project**
```bash
cd /mnt/d/School/NT137/Project
```

2. **Activate Virtual Environment**
```bash
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
# If Flask not in requirements, install separately:
pip install flask werkzeug
```

## Running the Application

### Start the Flask Server
```bash
source .venv/bin/activate  # Activate venv first
python3 app.py
```

### Default Access
```
Local URL: http://localhost:5000
Network URL: http://0.0.0.0:5000
```

### Production Deployment
For production, use a proper WSGI server:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Usage

### 1. Open Web Interface
Navigate to `http://localhost:5000` in your browser

### 2. Upload File
- **Drag & Drop**: Drag executable onto the upload area
- **Browse**: Click "Browse Files" button to select file
- **Supported**: EXE, DLL, BIN, SCR, SYS, COM files
- **Max Size**: 50MB

### 3. View Results

Once uploaded, the analysis automatically begins. Results include:

#### Summary Section
- Filename and file size
- Architecture (x86/x64/ARM)
- Entry point address

#### Obfuscation Score
- **0-30**: No or minimal obfuscation
- **30-50**: Possible obfuscation (yellow)
- **50-100**: Highly obfuscated (red)

#### Detailed Tabs

**Entropy Tab**
- Overall file entropy visualization
- Section-by-section breakdown
- Interpretation guide (0.0-8.0 scale)

**Sections Tab**
- All PE sections listed
- Virtual/raw addresses and sizes
- Access permissions
- Individual section entropy

**Imports Tab**
- Suspicious APIs highlighted in red
- All imported functions listed
- DLL names shown

**XOR Detection Tab**
- Potential XOR keys found
- Indicates presence of XOR-encoded strings

## API Endpoints

### POST /api/analyze
Analyzes uploaded executable file.

**Parameters:**
- `file` (multipart/form-data): Binary file to analyze

**Response:**
```json
{
  "filename": "malware.exe",
  "file_size": 65536,
  "pe_analysis": {
    "valid_pe": true,
    "architecture": "x86 (32-bit)",
    "entry_point": "0x1000",
    "sections": [...],
    "total_entropy": 7.45,
    "high_entropy_sections": [...],
    "imports": [...],
    "suspicious_imports": [...]
  },
  "xor_analysis": {
    "xor_keys": ["0x42", "0x55"],
    "max_strings": 2
  },
  "obfuscation": {
    "score": 75,
    "status": "HIGHLY OBFUSCATED",
    "color": "danger",
    "details": [...]
  }
}
```

## File Structure

```
/mnt/d/School/NT137/Project/
├── app.py                      # Flask application
├── templates/
│   └── index.html             # Main web interface (Bootstrap)
├── uploads/                    # Temporary uploaded files (auto-created)
├── requirements.txt           # Python dependencies
├── xor_detect_v2.py          # XOR detection module
├── pe_assembly_extractor.py  # PE analysis module
├── advanced_detection.py      # Advanced obfuscation detection
└── detect_obfuscation.py     # Obfuscation detection
```

## Obfuscation Detection Methods

The application detects obfuscation through multiple indicators:

### 1. **Entropy Analysis**
- Calculates Shannon entropy for file and each section
- High entropy (>7.2) indicates encryption/packing
- Ranges from 0 (repetitive) to 8 (random)

### 2. **Section Analysis**
- Examines PE sections for unusual characteristics
- Detects high-entropy code sections (typical of packed code)
- Identifies suspicious permission combinations

### 3. **API Detection**
- Scans imports for suspicious Windows APIs
- Flags code injection functions (VirtualAlloc, WriteProcessMemory)
- Identifies process manipulation APIs

### 4. **XOR Pattern Detection**
- Tests for XOR-encoded strings
- Identifies potential encryption keys
- Looks for malware signatures

### 5. **Import Analysis**
- Counts imported functions (packed files have few imports)
- Detects forward declarations and delayed loading

## Scoring System

Points awarded for obfuscation indicators:

| Indicator | Points | Severity |
|-----------|--------|----------|
| High entropy (>7.2) | +25 | HIGH |
| High-entropy sections | +20 | HIGH |
| Suspicious APIs | +15 | MEDIUM |
| XOR patterns | +20 | MEDIUM |
| Few imports (<10) | +10 | LOW |

**Total Score Interpretation:**
- **0-30**: Clean/Unobfuscated
- **30-50**: Possibly Obfuscated (Yellow)
- **50-100**: Highly Obfuscated (Red)

## Security Considerations

### ✅ Safe to Use With
- Known malware samples (in isolated environment)
- Legitimate executables for benchmarking
- Authorized security research binaries

### ⚠️ Warnings
- Run on isolated network for untrusted files
- Don't download/execute detected malware
- Use in sandboxed environment when possible
- Requires proper authorization for any testing

## Troubleshooting

### Flask Not Found
```bash
source .venv/bin/activate
pip install flask werkzeug
```

### Port 5000 Already in Use
```bash
python3 app.py --port 5001
# Or kill existing process:
lsof -i :5000
kill -9 <PID>
```

### Permission Denied on Upload
```bash
chmod 777 uploads
```

### File Upload Fails
- Check file size (<50MB)
- Verify file type (.exe, .dll, .bin, .scr, .sys, .com)
- Ensure upload folder has write permissions

### Slow Analysis
Large files (>30MB) may take time to analyze. Progress indicator shows "Analyzing..."

## Performance

- **Small Files (<5MB)**: <1 second
- **Medium Files (5-20MB)**: 1-3 seconds
- **Large Files (20-50MB)**: 3-10 seconds

## Browser Compatibility

✅ **Tested on:**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- Mobile browsers (responsive design)

## Advanced Configuration

### Change Upload Folder
Edit in `app.py`:
```python
UPLOAD_FOLDER = '/custom/path/uploads'
```

### Increase File Size Limit
Edit in `app.py`:
```python
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
```

### Debug Mode
```bash
export FLASK_DEBUG=1
python3 app.py
```

## Example Workflows

### Workflow 1: Quick Malware Check
1. Upload suspected malware
2. Check Obfuscation Score
3. If score >50, file is likely packed/obfuscated
4. Review suspicious imports for injection APIs

### Workflow 2: Detailed Analysis
1. Upload file
2. Check Entropy tab for overall encryption indicators
3. Review Sections tab for high-entropy code regions
4. Examine Imports tab for suspicious API calls
5. Check XOR tab for encoding patterns

### Workflow 3: Batch Testing
```bash
# Test multiple files via curl
for file in samples/*.exe; do
    curl -F "file=@$file" http://localhost:5000/api/analyze
done
```

## API Integration Example

### Python
```python
import requests

files = {'file': open('malware.exe', 'rb')}
response = requests.post('http://localhost:5000/api/analyze', files=files)
results = response.json()

print(f"Obfuscation Score: {results['obfuscation']['score']}")
print(f"Status: {results['obfuscation']['status']}")
```

### JavaScript
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('http://localhost:5000/api/analyze', {
    method: 'POST',
    body: formData
})
.then(r => r.json())
.then(data => console.log(`Score: ${data.obfuscation.score}`));
```

### cURL
```bash
curl -F "file=@malware.exe" http://localhost:5000/api/analyze
```

## Database/Logging

Currently stores analysis results in response only (no persistent storage). To add logging:

```python
import logging

logging.basicConfig(filename='analysis.log', level=logging.INFO)
logger = logging.getLogger(__name__)

# In analyze() route:
logger.info(f"Analyzed {filename}: Score {obfuscation_score}")
```

## Extension Ideas

- 📊 Save analysis history
- 📈 Trending obfuscation patterns
- 🔔 Automated alerts for high-risk files
- 📋 Batch processing queue
- 🗄️ Results database
- 🔗 Export to JSON/CSV
- 🌐 REST API key authentication
- 📱 Mobile app API

## License

This application is for educational and authorized security research only.

Use responsibly and legally.

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review Flask documentation: https://flask.palletsprojects.com/
3. Check pefile documentation: https://github.com/erocarrera/pefile
4. Review Capstone documentation: https://www.capstone-engine.org/

---

**Deobfuscator Web Interface** - Binary Obfuscation Detection System
Built for NT137 Project - Malware Analysis Course
