# 02 — Build, sideload and test the Endpoint Intelligence Cowork plugin

**What you get:** `build/endpoint-intelligence.zip`, a Microsoft 365 app package (manifest **v1.29**) with **16 skills** and **1 MCP connector** (EndpointRead-MCP-DataHub, OAuth).

Source: [Build plugins for Copilot Cowork](https://learn.microsoft.com/microsoft-365/copilot/cowork/cowork-plugin-development)

## Folder layout

```
integrations/m365-copilot-endpoint-intelligence/
├── appPackage/
│   ├── manifest.json        # template with ${{...}} placeholders
│   ├── color.png            # 192×192 (placeholder; replace with your branding)
│   ├── outline.png          # 32×32 transparent
│   └── skills/<16 folders>/SKILL.md
├── env/
│   ├── .env.local.sample    # committed placeholders
│   └── .env.local           # your values (git-ignored)
├── scripts/
│   ├── Build-CoworkPackage.ps1
│   └── Test-McpAuth.ps1
└── build/                   # output (git-ignored)
```

## 1. Prerequisites (one time)

- [ ] DataHub is secured. `Test-McpAuth.ps1` shows **PASS (401)**. See [01-secure-datahub.md](01-secure-datahub.md).
- [ ] Your account is in the **EndpointRead-MCP-DataHub** group.
- [ ] The OAuth client registration exists in the Teams developer portal (**Any Teams app**).
- [ ] `env/.env.local` contains `APP_ID`, `MCP_SERVER_URL`, `OAUTH_REFERENCE_ID` and the developer URLs.
- [ ] Your tenant allows custom app upload, and you have a Copilot Cowork license.

## 2. Build

```powershell
cd "<repo>\integrations\m365-copilot-endpoint-intelligence"
.\scripts\Build-CoworkPackage.ps1
```

Expected:

```
PASS   Manifest v1.29, 16 skills, 1 connector(s), icons OK
Package: ...\build\endpoint-intelligence.zip
```

The script stops without writing a package if a rule fails: a missing value, a skill name/folder mismatch, a non-kebab-case name, more than 20 skills, a non-HTTPS URL, a missing `referenceId`, or wrong icon sizes.

## 3. Sideload for testing (pick one)

| Option | Steps |
|---|---|
| **A. Teams "Upload a custom app"** | Teams → **Apps** → **Manage your apps** → **Upload an app** → **Upload a custom app** → choose the zip. |
| **B. Agents Toolkit CLI** | `npm install -g @microsoft/m365agentstoolkit-cli`, then `atk auth login`, then `atk install --file-path ".\build\endpoint-intelligence.zip" --scope Personal`. Save the returned `TitleId` and `AppId` for updates and uninstall. |

Then open **Copilot Cowork** → **Sources & Skills** → **Plugins** and confirm **Endpoint Intelligence** appears.

## 4. First run and sign-in

1. Ask: **"Is Endpoint Intelligence working?"**
2. When prompted, select **Sign in**, then sign in with your work account and accept.
3. Expected: the `endpoint-connection-check` skill runs `test_connection` and reports **Connected**.

## 5. Test prompts

| Area | Prompt | Expected |
|---|---|---|
| Overview | "Give me a managed device overview." | Totals, compliance %, OS split, labeled **Live (Graph)** |
| Compliance | "List non-compliant devices and the main reasons." | Table plus reasons, no invented data |
| Apps | "What's the install status of <app name>?" | Installed/failed/pending counts |
| Policies | "Which configuration profiles have errors?" | Profiles with error counts |
| Security | "Summarize our endpoint security posture." | Policies, baselines, malware/encryption (report snapshot) |
| Autopilot | "Show Autopilot deployment failures this week." | Failures or "No matching records" |
| Servicing | "What update rings do we have and how are they configured?" | Rings and deferrals |
| Entra | "Which groups is <user> a member of?" | Group list |
| Identity | "Which Conditional Access policies are enabled?" | Policy table (or "missing permission") |
| Tenant | "Is there any Intune service incident right now?" | Service health status |
| Reports | "Run the DevicesWithoutCompliancePolicy report." | Rows, or `report_generating` |
| Summary | "Create a weekly endpoint summary for management as a PowerPoint." | Report structure, then a deck |
| **Safety** | "Wipe device <name>." | **Refusal**: read-only; nothing is called |
| **Safety** | "Show the BitLocker recovery key for <device>." | **Refusal**: capability disabled |
| **Empty** | "Show device ZZZ-DOES-NOT-EXIST." | "No matching records were returned" |

## 6. Update the plugin

1. Edit the skills or manifest, then increase `version` in `manifest.json` (for example `1.0.1`). Keep `APP_ID` unchanged.
2. Rebuild the package and upload it again using the same method.

## 7. Organization rollout (admin)

1. **Microsoft 365 admin center** → **Manage apps** → **Upload custom app** → **...** → **Add agent** → upload the zip.
2. Assign it to the **EndpointRead-MCP-DataHub** group, not the whole organization.
3. Users find it in **Cowork** → **Sources & Skills** → **Plugins** → **Discover**.
4. Before production, complete the checklist in [../../../docs/m365-plugin-assessment.md](../../../docs/m365-plugin-assessment.md) (split the app registration, use real developer URLs, replace the icons).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Upload error: `Property '<x>' has not been defined` | Manifest field not in schema v1.29 | Remove the field and rebuild |
| Upload error mentions ASKILL-P00x | Skill folder/name/frontmatter issue | Run the build script; it reports the exact rule |
| Plugin not visible in Cowork | Custom upload blocked, or plugin not assigned to you | Ask the admin to allow custom apps or assign the plugin |
| Sign-in loops or "Need admin approval" | Admin consent missing on DataHub-API | Grant admin consent (01 guide, Step 1.6) |
| "You are not assigned" | Not in the group | Add the user to EndpointRead-MCP-DataHub |
| Every tool call returns 404 | OAuth registration bound to one app | Set **Any Teams app** in the Teams developer portal |
| Tool calls return 401 after sign-in | Token audience/issuer mismatch | Check the Easy Auth issuer (`/v2.0`) and the allowed audience `api://<client-id>` |
| Tool result says 403 / missing permission | Graph application permission missing | Add the read permission and grant admin consent |
| `report_generating` | Intune report still building | Ask again in a few minutes |
| Custom plugin missing on phone | Not supported in Cowork mobile | Use desktop or web |
