import pandas as pd

# Read the CSV file into a DataFrame
df = pd.read_csv("firewall_practice_logs.csv")


# Group the firewall logs by destination_port.
# This means all rows with the same destination port are placed into the same group.
port_summary = df.groupby("destination_port").agg(
    # Count how many total log entries exist for each destination port.
    connection_count=("destination_port", "count"),
    # Count how many unique source IPs connected to each destination port.
    unique_source_ips=("source_ip", "nunique"),
    # Create a sorted list of the unique source IPs that connected to each destination port.
    source_ips=("source_ip", lambda x: sorted(x.unique())),
    # Create a sorted list of the unique destination IPs that received traffic on each destination port.
    destination_ips=("destination_ip", lambda x: sorted(x.unique())),
)

# ---------Firewall Rule Suggestions-----------------
# source IP -> destination IP -> destination port
rule_summary = (
    df.groupby(["source_ip", "destination_ip", "destination_port"])
    .size()
    .reset_index(name="connection_count")
)

# Sort rule candidates by most frequent connections
rule_summary = rule_summary.sort_values("connection_count", ascending=False)


# Print the final summary tables
port_summary.to_excel("Firewall_Connections_Summary.xlsx")
rule_summary.to_excel("Firewall_Rules_Summary.xlsx")
print("Excel File created in current directory")
