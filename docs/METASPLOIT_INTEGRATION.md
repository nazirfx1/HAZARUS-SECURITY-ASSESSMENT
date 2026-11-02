# HAZARUS Security Assessment Framework

## Exploitation Subsystem Documentation

### Metasploit Integration Guide

#### Prerequisites

1. Install Metasploit Framework
```bash
sudo apt install metasploit-framework
```

2. Start msfrpcd
```bash
msfrpcd -P <your_password> -U <username>
```

Default configuration:
- Host: 127.0.0.1
- Port: 55553
- SSL: Disabled (configure in production)

#### Configuration

Add to `config/hazarus.yaml`:

```yaml
metasploit:
  host: "127.0.0.1"
  port: 55553
  username: "msf"
  password_env: "MSFRPC_PASSWORD"  # Read from environment variable
```

#### Security Best Practices

1. **Never hardcode passwords** - Use environment variables
2. **Bind to localhost** - Do not expose RPC publicly
3. **Use SSL** - Enable SSL for production deployments
4. **Rotate credentials** - Change RPC passwords regularly
5. **Monitor access** - Log all RPC connections

#### Module Execution Flow

1. Connect to msfrpcd
2. Authenticate with credentials
3. Search for module
4. Get module information
5. Validate target compatibility
6. Configure options
7. Execute module (check mode first)
8. Monitor execution
9. Capture output
10. Clean up sessions

#### Example Usage

```python
from exploitation.metasploit_rpc import MetasploitRPC

# Connect
msf = MetasploitRPC()
await msf.connect("msf", "password")

# Search
modules = await msf.search_modules("apache rce")

# Get info
info = await msf.get_module_info("exploit/multi/http/apache")

# Execute
job_id = await msf.execute_module(
    "exploit/multi/http/apache",
    {
        "RHOSTS": "192.168.100.10",
        "RPORT": 80,
        "TARGETURI": "/"
    }
)
```

### Lab Setup Instructions

#### Prerequisites

- VirtualBox or VMware
- Vulnerable VM images (Metasploitable, OWASP BWA, etc.)
- Network isolation (dedicated VLAN or virtual network)

#### Lab Network Configuration

1. Create isolated network: 192.168.100.0/24
2. Configure HAZARUS lab ranges
3. Deploy vulnerable VMs to lab network
4. Create clean snapshots

#### Recommended Lab Targets

- Metasploitable 2 (Linux)
- OWASP Broken Web Applications
- DVWA (Damn Vulnerable Web App)
- VulnHub images

#### Lab Target Template

```python
from exploitation.lab_executor import LabTarget

target = LabTarget(
    name="metasploitable2",
    ip="192.168.100.10",
    snapshot_name="clean",
    platform="linux",
    services=["http", "ssh", "ftp", "smb"],
    vulnerabilities=["CVE-2007-6336", "CVE-2012-1823"]
)
```

### Security Limitations

1. **No Autonomous Exploitation** - Framework does not automatically exploit
2. **Lab Only** - Exploitation restricted to lab environments
3. **Explicit Approval** - Each exploit requires operator approval
4. **Timeout Enforcement** - All exploits have hard timeouts
5. **Evidence Only** - Exploits capture evidence, do not maintain access
6. **Automatic Cleanup** - Lab targets restored to clean state

### Troubleshooting

#### msfrpcd Connection Failed

```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Restart msfrpcd
msfrpcd -P password -U username
```

#### Lab Target Not Verified

```bash
# Check IP is in lab range
ipcalc 192.168.100.10/24

# Add custom lab range in code
engine.add_lab_range("192.168.100.0/24")
```

#### Module Execution Timeout

- Increase timeout in configuration
- Check lab target network connectivity
- Verify module compatibility with target
