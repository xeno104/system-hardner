import subprocess
import re
from utils.policy_manager import update_field, save_policy

def snapshot_all_rules(policy, policy_path):
   
    for rule in policy.get("rules", []):
        rule_id = rule.get("id")
        if not rule_id:
            continue

        if "check_command" not in rule or not rule["check_command"]:
            print(f"⚠️ Skipping {rule_id}: No check_command")
            continue

        cmd = rule["check_command"][0]

        try:
            
            result = subprocess.check_output(f"cmd /c {cmd}", shell=True, text=True).strip()

           
            result_lower = result.lower()

            if result_lower in ["enabled", "true"]:
                value = 1
            elif result_lower in ["disabled", "false"]:
                value = 0
            else:
                
                match = re.search(r"\d+", result)
                value = int(match.group(0)) if match else result

       
            if "rollback_value" not in rule or not isinstance(rule["rollback_value"], list):
                rule["rollback_value"] = []

            
            update_field(policy, rule_id, ["rollback_value", 0], value)
            print(f"📝 Snapshot saved for {rule_id}: {value}")

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to run check_command for {rule_id}: {e}")

   
    save_policy(policy, policy_path)
