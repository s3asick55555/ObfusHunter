#!/usr/bin/env python3
"""
Deobfuscator - Web UI
Flask application for binary obfuscation detection
"""

import os
import sys
import json
import math
from pathlib import Path
from collections import Counter
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file
import pefile

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'bin', 'dll', 'scr', 'sys', 'com'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if not data:
        return 0
    entropy = 0
    byte_counts = Counter(data)
    for count in byte_counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def analyze_pe_file(file_path):
    """Analyze PE file and return results"""
    results = {
        'valid_pe': False,
        'architecture': None,
        'entry_point': None,
        'sections': [],
        'entropy': 0,
        'total_entropy': 0,
        'high_entropy_sections': [],
        'imports': [],
        'suspicious_imports': [],
        'error': None
    }
    
    try:
        pe = pefile.PE(file_path)
        results['valid_pe'] = True
        
        # Architecture
        if pe.FILE_HEADER.Machine == 0x14c:
            results['architecture'] = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0x8664:
            results['architecture'] = "x86-64 (64-bit)"
        elif pe.FILE_HEADER.Machine == 0x1c0:
            results['architecture'] = "ARM"
        else:
            results['architecture'] = f"Unknown (0x{pe.FILE_HEADER.Machine:04x})"
        
        results['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        
        # Read full file for overall entropy
        with open(file_path, 'rb') as f:
            file_data = f.read()
        results['total_entropy'] = calculate_entropy(file_data)
        
        # Section analysis
        suspicious_apis = [
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx",
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
        ]
        
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            
            section_info = {
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(entropy, 4),
                'actual_size': len(section_data),
                'characteristics': []
            }
            
            # Decode characteristics
            if section.Characteristics & 0x20000000:
                section_info['characteristics'].append("EXECUTE")
            if section.Characteristics & 0x40000000:
                section_info['characteristics'].append("READ")
            if section.Characteristics & 0x80000000:
                section_info['characteristics'].append("WRITE")
            
            results['sections'].append(section_info)
            
            # Flag high entropy sections
            if entropy > 7.2:
                results['high_entropy_sections'].append({
                    'section': name,
                    'entropy': round(entropy, 4),
                    'reason': 'Very high entropy - likely encrypted/packed'
                })
        
        # Import analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    api_name = imp.name.decode() if imp.name else "[unknown]"
                    results['imports'].append({'dll': dll_name, 'api': api_name})
                    
                    if any(sus in api_name for sus in suspicious_apis):
                        results['suspicious_imports'].append({'dll': dll_name, 'api': api_name})
        
    except pefile.PEFormatError:
        results['error'] = "Not a valid PE file"
    except Exception as e:
        results['error'] = str(e)
    
    return results


def detect_xor_strings(file_path, sample_size=8192):
    """Quick XOR detection analysis"""
    results = {
        'xor_keys': [],
        'max_strings': 0
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)
        
        # Test common keys
        targets = [
            b"http://", b"https://", b"cmd.exe", b"powershell.exe",
            b"VirtualAlloc", b"WriteProcessMemory"
        ]
        
        good_keys = set()
        for key in range(256):
            decoded = bytes([b ^ key for b in data])
            for target in targets:
                if target in decoded:
                    good_keys.add(key)
                    break
        
        results['xor_keys'] = sorted([f"0x{k:02x}" for k in good_keys])
        results['max_strings'] = len(good_keys)
        
    except Exception as e:
        results['error'] = str(e)
    
    return results


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze uploaded file"""
    
    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: ' + ', '.join(ALLOWED_EXTENSIONS)}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Perform analysis
        pe_analysis = analyze_pe_file(filepath)
        xor_analysis = detect_xor_strings(filepath)
        
        # Calculate obfuscation score
        obfuscation_score = 0
        obfuscation_details = []
        
        if pe_analysis['valid_pe']:
            # Check entropy
            if pe_analysis['total_entropy'] > 7.2:
                obfuscation_score += 25
                obfuscation_details.append({
                    'indicator': 'High Overall Entropy',
                    'value': round(pe_analysis['total_entropy'], 4),
                    'severity': 'HIGH',
                    'reason': 'File entropy >7.2 indicates encryption/packing'
                })
            
            # Check high entropy sections
            if pe_analysis['high_entropy_sections']:
                obfuscation_score += 20
                for section in pe_analysis['high_entropy_sections']:
                    obfuscation_details.append({
                        'indicator': f"High Entropy Section ({section['section']})",
                        'value': section['entropy'],
                        'severity': 'HIGH',
                        'reason': section['reason']
                    })
            
            # Check suspicious imports
            if pe_analysis['suspicious_imports']:
                obfuscation_score += 15
                obfuscation_details.append({
                    'indicator': 'Suspicious APIs',
                    'value': len(pe_analysis['suspicious_imports']),
                    'severity': 'MEDIUM',
                    'reason': 'Detected code injection/memory manipulation APIs'
                })
            
            # Check XOR patterns
            if xor_analysis['xor_keys']:
                obfuscation_score += 20
                obfuscation_details.append({
                    'indicator': 'XOR Encoding Detected',
                    'value': len(xor_analysis['xor_keys']),
                    'severity': 'MEDIUM',
                    'reason': f"Potential XOR keys found: {', '.join(xor_analysis['xor_keys'][:5])}"
                })
            
            # Check for few imports (packed indicator)
            if pe_analysis['imports'] and len(pe_analysis['imports']) < 10:
                obfuscation_score += 10
                obfuscation_details.append({
                    'indicator': 'Few Imports',
                    'value': len(pe_analysis['imports']),
                    'severity': 'LOW',
                    'reason': 'Typical for packed/obfuscated files'
                })
        
        # Determine obfuscation status
        if obfuscation_score >= 50:
            obfuscation_status = 'HIGHLY OBFUSCATED'
            obfuscation_color = 'danger'
        elif obfuscation_score >= 30:
            obfuscation_status = 'OBFUSCATED'
            obfuscation_color = 'warning'
        elif obfuscation_score > 0:
            obfuscation_status = 'POSSIBLY OBFUSCATED'
            obfuscation_color = 'info'
        else:
            obfuscation_status = 'NO OBFUSCATION DETECTED'
            obfuscation_color = 'success'
        
        response = {
            'filename': filename,
            'file_size': os.path.getsize(filepath),
            'pe_analysis': pe_analysis,
            'xor_analysis': xor_analysis,
            'obfuscation': {
                'score': obfuscation_score,
                'status': obfuscation_status,
                'color': obfuscation_color,
                'details': obfuscation_details
            }
        }
        
        # Cleanup
        try:
            os.remove(filepath)
        except:
            pass
        
        return jsonify(response)
    
    except Exception as e:
        try:
            os.remove(filepath)
        except:
            pass
        return jsonify({'error': str(e)}), 500


@app.template_filter('format_bytes')
def format_bytes(bytes_val):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} GB"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
