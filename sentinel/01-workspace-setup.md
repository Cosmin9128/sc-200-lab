# Microsoft Sentinel: Workspace Setup

Step-by-step guide for setting up a Microsoft Sentinel workspace for the SC-200 lab.

---

## Prerequisites

- Azure subscription (free trial or pay-as-you-go)
- Microsoft 365 E5 trial activated
- Global Administrator or Security Administrator role

## Step 1: Create Log Analytics Workspace

1. Go to Azure Portal > Log Analytics workspaces
2. Click "Create"
3. Settings:
   - Subscription: your subscription
   - Resource Group: create new "rg-sentinel-lab"
   - Name: "law-sentinel-lab"
   - Region: West Europe (closest to Romania)
4. Click "Review + Create" then "Create"

## Step 2: Enable Microsoft Sentinel

1. Go to Azure Portal > Microsoft Sentinel
2. Click "Create Microsoft Sentinel"
3. Select the workspace "law-sentinel-lab"
4. Click "Add"

## Step 3: Initial Configuration

After Sentinel is enabled:

- **Data retention:** Settings > Workspace Settings > set to 90 days (free tier)
- **Permissions:** Settings > Workspace Settings > Access Control > add your user as "Microsoft Sentinel Contributor"
- **Health monitoring:** Settings > Health and Audit > Enable

## Step 4: Verify Setup

```kql
Heartbeat
| where TimeGenerated > ago(1h)
| summarize count() by Computer
```

If you see results, the workspace is receiving data.

---

## Cost Management Tips

- M365 E5 trial gives you 27 days of free data ingestion for M365 logs
- Azure free credit ($200) covers Sentinel costs for the lab period
- Set a budget alert in Azure Cost Management at $10 to avoid surprises
- Delete the resource group after the lab to stop all charges

## Screenshots

_Add screenshots of your setup here as you complete each step._
