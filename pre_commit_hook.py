import sys
import re
import math
import os
import json

# Mock vulnerability database
VULN_DB = {
    "requests": ["2.25.0", "2.25.1"], # Mock vulnerable versions
    "lodash": ["4.17.20"],
    "urllib3": ["1.26.4"]
}

# Regex for standard private keys
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?!.*PRIVATE_KEY_REGEX).* PRIVATE KEY-----")

# Entropy calculation threshold
ENTROPY_THRESHOLD = 4.5
STRING_MIN_LENGTH = 20

def calculate_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def find_high_entropy_strings(line):
    """Find words in a line that might be high entropy secrets."""
    # Split by spaces, quotes, equals
    words = re.split(r'[\s"\'=]+', line)
    high_entropy = []
    for word in words:
        if len(word) >= STRING_MIN_LENGTH:
            # Check if it's mostly alphanumeric (simple heuristic)
            if re.match(r'^[a-zA-Z0-9_-]+$', word):
                entropy = calculate_entropy(word)
                if entropy > ENTROPY_THRESHOLD:
                    high_entropy.append((word, entropy))
    return high_entropy

def check_file_secrets(filepath):
    """Scan a file for private keys and high entropy strings."""
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # Check for private keys
                if PRIVATE_KEY_REGEX.search(line):
                    issues.append(f"Line {line_num}: Found potential Private Key.")

                # Check for high entropy strings
                entropy_strings = find_high_entropy_strings(line)
                if entropy_strings:
                    issues.append(f"Line {line_num}: Found high-entropy string (possible secret/API key).")
    except Exception as e:
        # Ignore files that can't be read as text (binary, etc.)
        pass
    return issues

def check_requirements_txt(filepath):
    """Check requirements.txt against vuln db."""
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Simple parsing for package==version
                parts = re.split(r'[=<>~]+', line)
                if len(parts) >= 2:
                    pkg = parts[0].strip()
                    ver = parts[1].strip()
                    if pkg in VULN_DB and ver in VULN_DB[pkg]:
                        issues.append(f"Line {line_num}: Vulnerable dependency '{pkg}=={ver}' found.")
    except Exception as e:
        pass
    return issues

def check_package_json(filepath):
    """Check package.json dependencies against vuln db."""
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}

            for pkg, ver in all_deps.items():
                # Strip typical semver prefixes for simple matching
                clean_ver = re.sub(r'^[\^~]', '', ver)
                if pkg in VULN_DB and clean_ver in VULN_DB[pkg]:
                    issues.append(f"Vulnerable dependency '{pkg}@{ver}' found.")
    except Exception as e:
        pass
    return issues

def main():
    if len(sys.argv) < 2:
        print("Usage: pre_commit_hook.py <file1> <file2> ...")
        sys.exit(0) # Not a failure if no files passed, just nothing to do

    files_to_check = sys.argv[1:]
    all_issues = {}

    for filepath in files_to_check:
        if not os.path.exists(filepath):
            continue

        file_issues = []

        # General secret scan
        secrets = check_file_secrets(filepath)
        if secrets:
            file_issues.extend(secrets)

        # Specific dependency checks
        basename = os.path.basename(filepath)
        if basename == "requirements.txt":
            vulns = check_requirements_txt(filepath)
            if vulns:
                file_issues.extend(vulns)
        elif basename == "package.json":
            vulns = check_package_json(filepath)
            if vulns:
                file_issues.extend(vulns)

        if file_issues:
            all_issues[filepath] = file_issues

    if all_issues:
        print("\n" + "="*50)
        print("🚨 DEVSECOPS PRE-COMMIT HOOK FAILED 🚨")
        print("="*50)
        print("Security risks found in the following files:\n")

        for filepath, issues in all_issues.items():
            print(f"📄 File: {filepath}")
            for issue in issues:
                print(f"   ❌ {issue}")
            print("")

        print("="*50)
        print("💡 REMEDIATION GUIDE:")
        print(" - Secrets/API Keys: Remove hardcoded secrets. Use environment variables (e.g., .env files) or a secret manager.")
        print(" - Private Keys: Never commit private keys. Remove them and rotate the key if it was already exposed.")
        print(" - Vulnerable Dependencies: Update the package to a non-vulnerable version.")
        print("="*50 + "\n")
        sys.exit(1)

    print("✅ DevSecOps pre-commit hook passed. No issues found.")
    sys.exit(0)

if __name__ == "__main__":
    main()
