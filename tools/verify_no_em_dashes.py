#!/usr/bin/env python3
"""
Verification tool to ensure zero em dashes exist in any comments or documentation.
Scans all text, code, markdown, and P4 files in the repository.
"""

import os
import sys

DISALLOWED_CHARS = ['\u2014', '\u2013']

def check_file(path):
    issues = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
        
    for line_idx, line in enumerate(lines, 1):
        for char in DISALLOWED_CHARS:
            if char in line:
                issues.append((line_idx, f"Disallowed dash unicode character U+{ord(char):04X}"))
                
        # Check comments or documentation
        stripped = line.strip()
        is_comment_or_doc = (
            path.endswith('.md') or 
            path.endswith('.txt') or
            stripped.startswith('//') or 
            stripped.startswith('/*') or 
            stripped.startswith('*') or 
            stripped.startswith('#')
        )
        if is_comment_or_doc and 'verify_no_em_dashes.py' not in path:
            if ' -' + '- ' in line:
                issues.append((line_idx, "Punctuation double-dash detected in comment or doc"))
            parts = line.split()
            for part in parts:
                if not part.startswith('--') and '--' in part:
                    subparts = part.split('--')
                    if len(subparts) == 2 and subparts[0].isalpha() and subparts[1].isalpha():
                        issues.append((line_idx, f"Punctuation double-dash connecting words detected: {part}"))
                        
    return issues

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    total_issues = 0
    scanned_count = 0
    
    for root, dirs, files in os.walk(repo_root):
        if '.git' in dirs:
            dirs.remove('.git')
        if '__pycache__' in dirs:
            dirs.remove('__pycache__')
            
        for file in sorted(files):
            if file.endswith(('.p4', '.py', '.md', '.txt', '.json', '.toml', '.sh', '.yaml', '.yml')):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_root)
                scanned_count += 1
                issues = check_file(file_path)
                if issues:
                    print(f"FAILED: {rel_path}")
                    for line_idx, msg in issues:
                        print(f"  Line {line_idx}: {msg}")
                    total_issues += len(issues)
                    
    print(f"Scanned {scanned_count} files.")
    if total_issues > 0:
        print(f"ERROR: Found {total_issues} dash issues across repository.")
        sys.exit(1)
    else:
        print("PASS: Zero disallowed dashes found across all files.")
        sys.exit(0)

if __name__ == '__main__':
    main()
