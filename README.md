# Router Fleet Health Checker

A Python-based network automation tool for validating router health across large-scale network environments.

## Features

- Supports Cisco IOS/XE/NX-OS, Arista EOS, and Juniper Junos
- Concurrent SSH connections using Netmiko
- Interface health validation
- BGP neighbor validation
- CPU and memory checks
- Route summary collection
- CSV and JSON report generation
- Logging
- Read-only operations (no configuration changes)

## Requirements

- Python 3.10+
- Netmiko

Install dependencies:

```bash
pip install netmiko
```

## Project Structure

```
router-fleet-health/
│
├── router_fleet_health.py
├── README.md
├── requirements.txt
├── inventory.csv
└── output/
```

## Inventory Example

```csv
name,host,device_type,port,username,expected_bgp_peers,expected_up_interfaces,max_cpu_percent,max_memory_percent
lab-r1,192.168.1.1,cisco_ios,22,admin,2,GigabitEthernet0/0;GigabitEthernet0/1,80,85
```

## Create Sample Inventory

```bash
python router_fleet_health.py --create-sample
```

## Run

```bash
python router_fleet_health.py --inventory inventory.csv --workers 20
```

## Output

The script generates:

- CSV report
- JSON report
- Log file

inside the `output/` directory.

## Workflow

```
Load Inventory
      │
      ▼
Connect to Router
      │
      ▼
Check Interfaces
      │
      ▼
Check BGP
      │
      ▼
Check CPU
      │
      ▼
Check Memory
      │
      ▼
Check Routes
      │
      ▼
Generate Report
```

## Future Improvements

- HTML dashboard
- Email notifications
- Slack / Microsoft Teams alerts
- SNMP health checks
- REST API support
- Grafana integration

## License

MIT License
