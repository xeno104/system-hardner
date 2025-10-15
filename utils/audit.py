import subprocess
import re
import platform
from utils.os_detect import detect_os

# Detect OS once at import time
os_name, os_version = detect_os()

def run_cmd_command(command):
    
    try:
        # Choose the right shell prefix
        if os_name == "windows":
            full_command = f'cmd /c "{command}"'
        else:
            full_command = f'bash -c "{command}"'

        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            shell=True
        )

        if result.returncode != 0:
            print(f"❌ Command failed: {command}")
            print(result.stderr.strip())
            return None

        return result.stdout.strip()

    except Exception as e:
        print(f"⚠️ Error running command '{command}': {e}")
        return None


def evaluate_logic(output, logic):
    
    try:
        # Extract numeric value if present
        match = re.search(r"\d+", output)
        if match:
            output_val = float(match.group())
        elif output.lower() in ['true', 'false']:
            output_val = output.lower() == 'true'
        else:
            output_val = output.strip()
    except Exception:
        output_val = output.strip()

    operator = logic.get("operator")

    try:
        if operator == "==":
            return output_val == float(logic.get("value"))
        elif operator == "!=":
            return output_val != float(logic.get("value"))
        elif operator == ">=":
            return output_val >= float(logic.get("value"))
        elif operator == "<=":
            return output_val <= float(logic.get("value"))
        elif operator == "range":
            return float(logic.get("min")) <= output_val <= float(logic.get("max"))
        elif operator == "contains":
            return str(logic.get("value")) in str(output_val)
        else:
            return False
    except Exception:
        return False


def audit_rule(rule):
    
    if not rule.get("enabled", False):
        return [rule['id'], "Skipped"]

    
    if os_name == "windows":
        commands = rule.get("check_command_win") or rule.get("check_command")
    else:
        commands = rule.get("check_command_linux") or rule.get("check_command")

    if not commands:
        return [rule['id'], "No check command found"]

    for cmd in commands:
        output = run_cmd_command(cmd)
        if output is None:
            return [rule['id'], "Error"]

        compliant = evaluate_logic(output, rule.get("logic", {}))
        if compliant:
            return [rule['id'], "Compliant"]
        else:
            return [rule['id'], "Non-compliant"]

    return [rule['id'], "No check command found"]


def audit_policy(policy, level):
    
    results = []

    level = level.lower()

   
    levels = policy.get("levels", {})
    level_rule_ids = levels.get(level, [])

    if not level_rule_ids:
        print(f"⚠️ No rules found for level: {level}")
        return []

    print(f"🧠 Auditing {len(level_rule_ids)} rules for level: {level.capitalize()}")

    for rule in policy.get("rules", []):
        
        if rule.get("id") not in level_rule_ids:
            continue

        result = audit_rule(rule)
        results.append(result)

    return results

