# Asset Inventory Template — VRA

This CSV is the **ground truth** about your infrastructure. VRA uses it to:
- Assign correct asset criticality to risk scores
- Flag internet-exposed assets for higher risk scoring
- Route remediation jobs to the correct business owner
- Compute SLAs per business unit / environment

## Required columns

| Column | Required | Values | Used by |
|---|---|---|---|
| `asset_id` | No (auto-generated if blank) | UUID or any unique string | All modules |
| `hostname` | Yes | DNS hostname, e.g. `web-prod-01` | M1 ingest mapping |
| `ip_address` | Yes | IPv4 or IPv6 | M1 ingest mapping |
| `business_unit` | Yes | Free text, e.g. `IT`, `Finance`, `Engineering` | M4 job grouping |
| `business_owner` | Recommended | Email of the team responsible | M10 ticketing |
| `criticality` | Yes | `low` / `medium` / `high` / `critical` | M3 risk score (×15) |
| `internet_exposed` | Yes | `true` / `false` | M3 risk score (×10) |
| `environment` | Recommended | `production` / `staging` / `dev` | M4 SLA policy |

## How to fill it

### From Active Directory (Windows domain)
```powershell
Get-ADComputer -Filter * -Properties IPv4Address,Description,OperatingSystem |
  Select-Object @{N='hostname';E={$_.Name}},
                @{N='ip_address';E={$_.IPv4Address}},
                @{N='business_unit';E={'IT'}},
                @{N='criticality';E={'medium'}},
                @{N='internet_exposed';E={'false'}},
                @{N='environment';E={'production'}} |
  Export-Csv -Path asset_inventory.csv -NoTypeInformation
```

### From AWS EC2
```bash
aws ec2 describe-instances --query \
  'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,PrivateIpAddress,PublicIpAddress!=null && `true` || `false`,Tags[?Key==`Environment`]|[0].Value]' \
  --output text > aws_assets.tsv
```

### From Ansible inventory
```bash
ansible-inventory --list -y | python -c "
import yaml, sys, csv
data = yaml.safe_load(sys.stdin)
# … extract hosts and write to CSV
"
```

### Manually via the UI
After VRA is running, open http://localhost:5173/assets and use the Add Asset form. This writes directly to the database — no CSV needed.

## After editing

1. Save as `data/input/asset_inventory.csv` (overwrite the existing file).
2. Restart the API (`Ctrl-C` then `python run_api.py`) — the migration will seed new assets into the database.
3. Re-run the pipeline OR re-upload your scan file via the Upload page.
