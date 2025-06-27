# 🛡️ DISA STIG Remediation on Windows 10 using Tenable & PowerShell

## 📌 Project Overview

This project demonstrates how to identify and remediate a Windows 10 DISA STIG finding using **Tenable Vulnerability Management** and **PowerShell scripting**. The finding in question, **WN10-SO-000100**, relates to enforcing **SMB packet signing** on the Windows SMB client to prevent man-in-the-middle attacks.

---

## 🛠️ Tools Used

- **Microsoft Azure** — Hosted the Windows 10 test VM  
- **Windows 10** — Target operating system for STIG compliance  
- **Tenable Vulnerability Management** — Performed STIG scan (DISA Microsoft Windows 10 STIG v3r4)  
- **PowerShell** — Automated registry remediation  
- **Windows Registry Editor** — Manual review and verification  

---

## 📋 STIG Under Review: `WN10-SO-000100`

> The Windows SMB client must be configured to always perform SMB packet signing.

- **Registry Path:**  
  `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

- **Value to Set:**  
  `RequireSecuritySignature=1 (REG_DWORD)`

![STIG Details](screenshots/11.%20This%20first%20STIG%20to%20fix%20with%20the%20ID%20of%20WN10-SO-000100.png)

---

## 🔄 Step-by-Step Process

### ✅ Step 1: Provision Azure Windows 10 VM
- Used Azure to create a clean test environment.
- *Purpose: Isolate the STIG test on a secure cloud-based instance.*

![1 Created VM](https://github.com/user-attachments/assets/aa63048b-966a-4cc2-a27f-852b0e4671af)

---

### 🔥 Step 2: Disable Firewall Temporarily
- Disabled Windows Firewall to allow Tenable credentialed scan to run smoothly. 
- *Purpose: Avoid interference with credential authentication during scans.*

![2 Disabling Firewall Rules](https://github.com/user-attachments/assets/ae2a7dd3-69a3-4c33-9ddd-84de04caf953)

---

### 🧪 Step 3: Create Tenable Scan

![4  Advanced Network Scan](https://github.com/user-attachments/assets/33fa86ce-9f7d-4f5d-a10b-332560de3b6d)

- Scan Template: **Advanced Network Scan**
- *Purpose: Configure a flexible scan that supports STIG compliance audits.*

![4  Advanced Network Scan](https://github.com/user-attachments/assets/be077519-bffc-4890-b822-0827d805607e)

---

### 🎯 Step 4: Target the VM’s Private IP
- Named it as: Stig-Implementation-Felipe and Set as a Internal Scan Type

![5  Editing Scan as Internal](https://github.com/user-attachments/assets/4bc801b3-e513-422f-b32c-64ae6dc96187)

- Targeted IP: `10.0.0.172`
- *Purpose: Pinpoint Tenable scan to the correct Windows 10 VM.*

![6  The private IP from VM as the Target for the scan](https://github.com/user-attachments/assets/45bab877-b6e0-47d0-b893-3df3716d3664)

---

### 🔐 Step 5: Add Valid Admin Credentials
- Used admin credentials (`labuser`) with full access to registry and services.
- *Purpose: Enable Tenable to perform registry-level checks for compliance.*

![7  Adding Credentials](https://github.com/user-attachments/assets/83d1c766-4a3e-42cb-aba1-c6d9cb4881f4)

---

### 📋 Step 6: Select Compliance & Plugin
- **Compliance Check:** DISA Microsoft Windows 10 STIG v3r4

![8  Selecting only the Windows 10 STIG as the compliance](https://github.com/user-attachments/assets/0e67e1c9-a363-4b8a-9a36-15cdcdd827c6)

- **Plugins:** Only enabled **Windows Compliance Checks**
- *Purpose: Ensure STIG alignment with faster scanning for lab efficiency.*

![9  In Plugins only enable Windows Compliance just go faster for the sake of the lab](https://github.com/user-attachments/assets/32178d21-37f8-4263-8745-d192d561cd0c)

---

### 🚀 Step 7: Launch Initial Scan
- *Purpose: Establish a compliance baseline before remediation.*

![10  Launching first scan](https://github.com/user-attachments/assets/9442c8c2-a3f4-4af0-90ed-5e0c5cfffbfb)

---

### ❌ Step 8: Confirm STIG Fails Initially
- *Purpose: Validate the system is non-compliant to begin with.*

![11  This first STIG to fix with the ID of WN10-SO-000100](https://github.com/user-attachments/assets/564b5f86-dfa8-4193-9132-7ffad44ef4a3)

---

### 🔎 Step 9: Manual Registry Check
- Found the STIG in the Internet and used this page as guide to **remediate** the vulnerability
- **STIG Under Review: `WN10-SO-000100`**

> The Windows SMB client must be configured to always perform SMB packet signing.

- **Registry Path:**  
  `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

- **Value to Set:**  
  `RequireSecuritySignature=1 (REG_DWORD)`

![12  Found the ID from STIG to fix](https://github.com/user-attachments/assets/f95d94d3-f135-428a-bd6e-80f25c12a3e0)

- Process of Finding the vulnerability in the Registry Editor from VM

![13  Process of remediating the STIG](https://github.com/user-attachments/assets/a722a01f-0819-4c7f-b2e7-b7303aff42d7)

- Remediate by setting the value of `RequireSecuritySignature` to `0`.
*Purpose: Verify Tenable’s result with the actual Windows registry.*

![14  Remediating STIG](https://github.com/user-attachments/assets/fc71a658-60d2-4133-9703-af69441fe7b4)

### 🛠️ Step 10: Ran the Scan Again After Remediation
-  **Ran the scan again after remediating the vulnerability to make sure it was remediated**

![15  Ran the scan again after remediating the STIG](https://github.com/user-attachments/assets/823d8f29-1bb6-43d6-a41a-81e704cf70a5)

- Results showing that the vulnerability was remediated successfully

![16  Result after remediating and scanning the STIG](https://github.com/user-attachments/assets/f5c37572-0585-4932-aa81-21182c8714e9)

### ❌ Step 11: Setting it Back to How It Was

- After the second scan I decided to changed the **"value data"** to **"0"** so I could rescan it again to make sure I could fail it again

![17  After second I changed it back to 0 so the scan show again that the STIG needs remediation](https://github.com/user-attachments/assets/63e41e37-6c2d-445a-95bf-eb69dac7cc13)

- Ran the third scan and here are the results showing that it failed again

![18  After the third scan it shows that the STIG needs to be remediated again](https://github.com/user-attachments/assets/90fa0841-789f-4d1f-9aa6-ce73b5e88cf6)
  
---

### ⚙️ Step 11: Apply Remediation via PowerShell

- Copied and pasted the key on my notepad so I could find a Powershell script to remediate again the vulnerability

![19  Saved The key to find a Powershell Script to remediate again the STIG after the latest scan](https://github.com/user-attachments/assets/4dc3f212-8030-4415-8ea7-b84ca47b8d8c)

- Back to the VM, after crafting and using some help with the Powershell script, I've used this to remediate again the vulnerability
```powershell
# Define the registry path
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

# Ensure the path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}

# Set DWORD values
Set-ItemProperty -Path $regPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord
Set-ItemProperty -Path $regPath -Name "EnableSecuritySignature" -Value 1 -Type DWord

- 
Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1 -Type DWord

# Set Expandable String
$serviceDllValue = "%SystemRoot%\System32\wkssvc.dll"
Set-ItemProperty -Path $regPath -Name "ServiceDll" -Value $serviceDllValue -Type ExpandString

Write-Host "Registry values have been configured successfully."
```
- Ran the script in **PowerShell ISE**

![20  Back in the VM Ran this Powershell Script to fix the STIG Again](https://github.com/user-attachments/assets/f4f04d84-3f96-4a70-b59c-424e41f8fdce)

- Made sure that the script actually worked by checking the **"value data"**

![21  After Running the Powershell script the STIG was remediated again](https://github.com/user-attachments/assets/102bf59d-08ad-401c-86bf-3acfa007b288)

- After that I restarted the VM and launched the last scan after remediating with a PowerShell Script
**Results:**

![22  After last scan the results shows that the PowerShell Script worked and the STIG was Remediated](https://github.com/user-attachments/assets/f10307e1-a473-4dbc-8fdf-11a0a7e444e2)

 
