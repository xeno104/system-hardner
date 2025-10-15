import yaml
import os

def load_policy(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Policy file not found: {path}")
    with open(path, "r") as f:
        policy = yaml.safe_load(f)
    return policy

def save_policy(policy, path):
    with open(path, "w") as f:
        yaml.dump(policy, f, sort_keys=False, allow_unicode=True)
    print(f"Policy saved: {path}")

def update_field(policy, rule_id, path, value):
    """
    Update a field in a rule safely. path is a list of keys or indices.
    Example paths:
      ["severity"] → top-level field
      ["rollback_value", 0] → first element of rollback_value list
    """
    for rule in policy.get("rules", []):
        if rule.get("id") != rule_id:
            continue

        target = rule
        for key in path[:-1]:
            if isinstance(target, dict):
                if key not in target:
                    target[key] = {} if not isinstance(path[path.index(key)+1], int) else []
                target = target[key]
            elif isinstance(target, list) and isinstance(key, int):
                while len(target) <= key:
                    target.append(None)
                target = target[key]
            else:
                raise TypeError(f"Cannot traverse path at {key} in {target}")

        last_key = path[-1]
        if isinstance(target, dict):
            target[last_key] = value
        elif isinstance(target, list) and isinstance(last_key, int):
            while len(target) <= last_key:
                target.append(None)
            target[last_key] = value
        else:
            raise TypeError(f"Cannot set value at {last_key} in {target}")

        print(f"✅ Updated rule {rule_id}: {path} → {value}")
        return
    raise ValueError(f"Rule ID {rule_id} not found")
