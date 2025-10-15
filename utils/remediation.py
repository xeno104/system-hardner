import subprocess
from utils.policy_manager import save_policy
from utils.snapshot import snapshot_all_rules
from utils.os_detect import detect_os
from utils.logger import setup_logger

def remediate_all_rules(policy, policy_path, level):
    """
    Applies remediation commands only for rules in the selected security level.

    Args:
        policy (dict): Loaded policy dictionary.
        policy_path (str): Path to the policy YAML file.
        level (str): Current security level (Basic, Moderate, Strict).

    Returns:
        list: List of results dictionaries containing id, status, and details.
    """
    # Initialize logger
    logger = setup_logger("SystemHardener")
    
    # Take a snapshot before remediation
    snapshot_all_rules(policy, policy_path)
    
    results = []

    os_name, os_version = detect_os()
    logger.info(f"Detected OS: {os_name} {os_version}")

    all_rules = policy.get("rules", [])
    if not all_rules:
        logger.warning("No rules found in policy")
        return []

    # Get list of rule IDs for the selected level from policy['levels']
    level_rule_ids = policy.get("levels", {}).get(level.lower(), [])

    for rule in all_rules:
        rule_id = rule.get("id")
        if not rule_id:
            continue

        # Skip rules not in the selected level
        if rule_id not in level_rule_ids:
            results.append({
                "id": rule_id,
                "status": "skipped",
                "details": f"Skipped (not in {level} level)"
            })
            logger.info(f"Skipped remediation for rule {rule_id}: not in {level} level")
            continue

        remediation_cmds = rule.get("remediation_command", [])
        if not remediation_cmds:
            results.append({
                "id": rule_id,
                "status": "skipped",
                "details": "No remediation_command"
            })
            logger.info(f"Skipped remediation for rule {rule_id}: No remediation_command")
            continue

        value = rule.get("default_remediation_value", "")

        for cmd in remediation_cmds:
            cmd_to_run = cmd.replace("{value}", str(value))

            # Choose proper shell for OS
            if os_name == "windows":
                full_cmd = f'cmd /c "{cmd_to_run}"'
            else:
                full_cmd = f"bash -c \"{cmd_to_run}\""

            logger.info(f"Executing remediation for rule {rule_id}: {full_cmd}")

            try:
                result = subprocess.run(
                    full_cmd,
                    shell=True,
                    check=True,
                    text=True,
                    capture_output=True
                )
                status = "success"
                details = result.stdout.strip() or f"Executed: {cmd_to_run}"

            except subprocess.CalledProcessError as e:
                status = "failed"
                stderr_msg = e.stderr.strip() if e.stderr else "No error message"
                details = f"Exit code {e.returncode}: {stderr_msg}"

            except Exception as e:
                status = "error"
                details = str(e)

            results.append({
                "id": rule_id,
                "status": status,
                "details": details
            })
            logger.debug(f"{rule_id} → {status}: {details}")

    # Save updated policy
    save_policy(policy, policy_path)

    return results
