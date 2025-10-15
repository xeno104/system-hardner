import csv
from datetime import datetime

def generate_report(audit_results, policy, csv_filename=None):
   
    policy_dict = {rule['id']: rule for rule in policy.get('rules', [])}

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nAUDIT REPORT - {timestamp}\n")

    headers = ["Policy ID", "Category", "Title", "Parameter", "Severity", "Level", "Result"]
    print(" | ".join(f"{h:<20}" for h in headers))
    print("-" * (len(headers) * 22))

    csv_rows = []
    for entry in audit_results:
        policy_id, result = entry
        rule = policy_dict.get(policy_id, {})
        category = rule.get("category", "")
        title = rule.get("title", "")
        param = rule.get("parameter_name", "")
        severity = rule.get("severity", "")
        level = rule.get("level", "")

        print(f"{policy_id:<20} | {category:<20} | {title:<20} | {param:<15} | {severity:<10} | {level:<10} | {result:<20}")

        csv_rows.append([policy_id, category, title, param, severity, level, result, timestamp])
    
    if csv_filename:
        with open(csv_filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers + ["Timestamp"])
            writer.writerows(csv_rows)
        print(f"\n✅ Audit report saved to {csv_filename}")
