import subprocess
import re

def get_switches():
    try:
        result = subprocess.run(
            ["sudo", "ovs-vsctl", "list-br"],
            capture_output=True,
            text=True,
            check=True
        )
        switches = result.stdout.strip().splitlines()
        return switches
    except subprocess.CalledProcessError as e:
        print("Error retrieving switch list:", e)
        return []

def get_flow_rules(switch):
    try:
        result = subprocess.run(
            ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving flow rules from switch {switch}:", e)
        return []

    filtered_lines = []
    for line in lines:
        if (
            ("ip" in line or "tcp" in line or "udp" in line or "icmp" in line)
            and ("flood" not in line)
            and ("CONTROLLER" not in line)
        ):
            # Remove n_packets=<number>, n_bytes=<number>
            modified_line = re.sub(r'n_packets=\d+,\s*n_bytes=\d+', '', line)
            modified_line = modified_line.strip()
            filtered_lines.append(modified_line)
    return filtered_lines

def main():
    all_rules = []
    switches = get_switches()
    if not switches:
        print("No running switches found.")
    else:
        for switch in switches:
            rules = get_flow_rules(switch)
            if rules:
                all_rules.append(f"Switch: {switch}")
                all_rules.extend(rules)
                all_rules.append("")

    with open("flow_table.txt", "w") as f:
        f.write("\n".join(all_rules))
    print("flow_table.txt has been created.")

if __name__ == "__main__":
    main()

