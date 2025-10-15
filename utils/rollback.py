import subprocess
from utils.policy_manager import update_field, save_policy
from utils.snapshot import snapshot_all_rules

def rollback_all_rules(policy, policy_path):
    """
    Rollback all rules using their rollback_value.
    Updates policy in memory and saves it.
    """

 
    results = []

    for rule in policy.get("rules", []):
        rule_id = rule.get("id")
        if not rule_id:
            continue


        if "remediation_command" not in rule or not rule["remediation_command"]:
            results.append({"id": rule_id, "status": "skipped", "details": "No remediation_command"})
            continue

        rollback_values = rule.get("rollback_value", [])

        if not rollback_values:
            results.append({"id": rule_id, "status": "skipped", "details": "No rollback_value"})
            continue

        for i, cmd in enumerate(rule["remediation_command"]):
           
            value = rollback_values[i] if i < len(rollback_values) else rollback_values[0]
            cmd_to_run = cmd.replace("{value}", str(value))

            try:
                subprocess.run(f"cmd /c {cmd_to_run}", shell=True, check=True, text=True)
                status = "success"
                details = f"Rollback executed: {cmd_to_run}"
            except subprocess.CalledProcessError as e:
                status = "failed"
                details = f"Exit code {e.returncode}: {cmd_to_run}"
            except Exception as e:
                status = "error"
                details = str(e)

            results.append({"id": rule_id, "status": status, "details": details})
            print(f"{rule_id} → {status}: {details}")


    save_policy(policy, policy_path)
    return results
