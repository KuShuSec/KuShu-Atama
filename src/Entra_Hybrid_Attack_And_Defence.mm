<map version="0.9.0">
  <node TEXT="Entra Hybrid Attack And Defence">
    <node TEXT="Initial Access">
      <node TEXT="AiTM Phishing">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Evilginx2 (proxy steals credentials and session cookies), Modlishka, and Muraena - popular adversary-in-the-middle frameworks"></node>
          <node TEXT="Abuse legitimate OIDC tools (e.g. custom reverse proxies, “EvilProxy” kits) to orchestrate AiTM phishing."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Enforce phishing-resistant MFA (FIDO2, Windows Hello for Business, or certificate-based auth)"></node>
          <node TEXT="Enable mfa fatigue protection such as number matching and additional context so users cannot be tricked by endless prompts"></node>
          <node TEXT="Implement Conditional Access policies to block legacy auth and require MFA for risky login locations."></node>
          <node TEXT="Consider Continuous Access Evaluation so stolen tokens get invalidated quickly on risk events."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Email Security: Block phishing emails and known AiTM kits."></node>
          <node TEXT="CASB: Monitor unusual session patterns (impossible travel, atypical MFA claims)."></node>
          <node TEXT="EDR: Can detect browser credential theft attempts."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Microsoft 365 Defender cross-domain alerts identify cookie theft and reuse (e.g. 'Stolen session cookie was used' alert)"></node>
          <node TEXT="Entra sign-in logs can reveal anomalous session usage (same Session ID used from different locations) if correlated via linkable identifiers"></node>
          <node TEXT="Gap: Entra Identity Protection alone doesn't flag AiTM token replay (looks like normal sign-in) without cross-product telemetry."></node>
          <node TEXT="New linkable session ID (SID) in Entra ID logs helps tie together all tokens from one authentication session, making it easier to spot a stolen session cookie reused elsewhere"></node>
          <node TEXT="The Authentication Methods activity preview can reveal suspicious MFA changes (attackers adding a new MFA method post-phish), which aids persistence detection."></node>
        </node>
      </node>
      <node TEXT="Device Code Flow Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals and TokenTactics can programmatically initiate the device code flow and capture tokens (TokenTactics will wait for a user to enter the code and then grab the token)"></node>
          <node TEXT="Attackers may also simply use Azure CLI (az login --use-device-code) or PowerShell to generate a device code URL, leveraging these legitimate tools to conduct the attack."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Maester"></node>
          <node TEXT="Disable device code flow for users if not needed (CA policy to block Device Code flow or scope it tightly)."></node>
          <node TEXT="Educate users that device login codes should only be entered into Microsoft's legitimate device login page."></node>
          <node TEXT="Require MFA even on device code flow (Conditional Access can treat device code sign-ins as requiring compliant device or MFA if possible)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Conditional Access (Authentication flows condition) - block or restrict Device Code flow usage tenant-wide"></node>
          <node TEXT="Use SIEM to detect patterns (e.g. spike in device code logins)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra sign-in logs (interactive user sign-ins via device code appear in logs with 'DeviceAuth' grant)."></node>
          <node TEXT="SIEM/SOAR can be used to hunt for multiple Device Code authentications or unusual client app usage."></node>
          <node TEXT="These authentications look like legitimate user logins, so out-of-the-box alerts are rare - requires monitoring of audit logs for unexpected usage."></node>
        </node>
      </node>
      <node TEXT="Illicit OAuth Consent Grants">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers often create a malicious multi-tenant app and send the OAuth consent link to users (no special tool needed beyond a crafted URL)."></node>
          <node TEXT="Tools like ROADtools can be used to automate token handling after consent."></node>
          <node TEXT="In some cases, custom phishing frameworks facilitate the OAuth consent scam by mimicking the Microsoft consent screen."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Disable user consent for most apps - use admin consent workflow so that users cannot grant permissions to unvetted apps."></node>
          <node TEXT="If user consent must be allowed, limit it to low-permission scopes and require admin approval for any high-impact permission."></node>
          <node TEXT="Encourage use of Publisher Verification (so users see a verified publisher badge) and leverage Entra consent policies (e.g. block consent to unverified apps or to certain sensitive permissions)."></node>
          <node TEXT="Regularly audit enterprise applications and remove any unnecessary or suspicious ones."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="CASB - monitors OAuth apps and can flag risky or rare apps."></node>
          <node TEXT="Entra Identity Protection will flag known malicious app consent if Microsoft has threat intelligence (and risky OAuth app policies can be configured)."></node>
          <node TEXT="There are also scripts (PowerShell/Graph) to enumerate consents for review (e.g., Office 365 IT Pros scripts)."></node>
          <node TEXT="Maester"></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Audit Logs record user consent events (look for 'Consent to application' entries)"></node>
          <node TEXT="CASB can alert on OAuth apps with unusual privileges or multiple user consents"></node>
          <node TEXT="Gap: If a single user consents to a malicious app and the app's activity blends in with normal API calls, it may not trigger immediate alerts without specific monitoring."></node>
        </node>
      </node>
      <node TEXT="Device Join Abuse (Hybrid and Emtra Join)">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals can simulate device registration via Graph API using a compromised user token."></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="ROADtools and custom Graph scripts can create device objects if the account has the device enrollment permission."></node>
          <node TEXT="In many cases, attackers abuse normal APIs (Microsoft Graph or legacy AD join interfaces), so there's no special 'exploit tool' needed beyond scripting the device join with stolen credentials."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Restrict device join rights - e.g. set “Users may join devices to Entra” to None or a limited group."></node>
          <node TEXT="Reduce the default limit of 50 devices per user (set it to 0 for most users who should not join devices)."></node>
          <node TEXT="Use Entra Privileged Identity Management for the Global Administrator or Intune roles that can join or register devices on others' behalf."></node>
          <node TEXT="If hybrid join, secure the Entra Connect configuration to prevent unauthorized writes."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="MDM enrollment restrictions - ensure only authorized users or managed processes can register devices."></node>
          <node TEXT="Entra device governance (no native tool, but you can script checks for bulk device joins)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Audit Logs show new device registrations (including who registered and device details)."></node>
          <node TEXT="Unusual patterns (e.g. a new device join by a user who already has a joined device, or joins outside normal IT processes) should be investigated."></node>
          <node TEXT="In hybrid cases, monitor on-premises AD for unexpected computer object creations."></node>
          <node TEXT="Gap: If an attacker uses a compromised account that is allowed to join devices, the event appears legitimate unless reviewed."></node>
        </node>
      </node>
      <node TEXT="Device Compliance Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals (and similar frameworks) can manipulate device compliance via the Graph API - for instance, an attacker with the right role could call the API to mark a device as compliant"></node>
          <node TEXT="Tools like TokenTactics(and V2) and custom PowerShell can also interface with Intune's API to acquire a token and update compliance status. Essentially, attackers misuse legitimate Graph calls to fake compliance."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Tie compliance to something that's hard to fake. For example, require a compliance check that involves device attestation or a TPM-backed signal, not just a simple policy flag."></node>
          <node TEXT="use conditional access requiring both “compliant” and “Hybrid Entra joined” (or a domain joined requirement) - this makes it much harder to spoof with just a flipped compliance flag."></node>
          <node TEXT="Limit which accounts can manage Intune compliance policies."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Microsoft Defender for Endpoint (MDE) integration - use device risk signals in Conditional Access."></node>
          <node TEXT="If a device is not truly healthy (even if marked compliant), EDR can flag it as risky and isolate it - if using MDE, it can make CA block it."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Intune compliance logs - track when a device's compliance status changes (who marked it compliant, and did it happen without the usual checks?)."></node>
          <node TEXT="Entra sign-in logs will show a previously non-compliant device suddenly being treated as compliant in Conditional Access decisions."></node>
          <node TEXT="Gap: An attacker with Intune admin rights could flip compliance on a device; this administrative action might only be in audit logs and not raise an immediate alert."></node>
        </node>
      </node>
      <node TEXT="Password Spraying">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals (PowerShell module) includes password spray functions."></node>
          <node TEXT="MailSniper is an open-source tool that can spray credentials against Exchange/O365 endpoints."></node>
          <node TEXT="MSOLSpray and similar scripts specifically target Entra/M365."></node>
          <node TEXT="Attackers may also use generic tooling like Burp or Hydra against exposed endpoints - or even legitimate Outlook Web Access pages - making the activity blend in with normal traffic."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Maester"></node>
          <node TEXT="Disable legacy authentication protocols - many password sprays target SMTP, IMAP, etc., which bypass MFA. Blocking legacy auth in Conditional Access thwarts this common tactic"></node>
          <node TEXT="Enforce MFA for all users, so a sprayed password alone isn't sufficient to breach."></node>
          <node TEXT="Use strong, unique passwords or passphrases to reduce success probability."></node>
          <node TEXT="Monitor and limit failed login attempts - Entra's smart lockout is on by default (locks out attacker while not impacting the real user)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Entra Smart Lockout - automatically blocks further attempts from an IP after a threshold of failed logins (tuned to distinguish legitimate users vs attackers)."></node>
          <node TEXT="Entra Identity Protection - can pre-empt known bad addresses (e.g., those on known malicious IP lists) and impose risk-based policies (like requiring MFA or blocking if risk is high)."></node>
          <node TEXT="For on-prem AD, enable AD FS Extranet Lockout if applicable (to protect against password spray via federated endpoints)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra sign-in logs - detect the pattern of a single IP attempting logins for many different accounts (horizontal spray) or many passwords against one account (vertical guessing)."></node>
          <node TEXT="On-premises AD (if federated or in hybrid scenarios) can trigger Defender for Identity brute-force alerts - for example, a massive number of LDAP simple bind failures will trigger a brute force alert. You can emulate in your SIEM/SOAR."></node>
          <node TEXT="Entra Identity Protection also flags “Password spray risk” in some cases (look for risk events like “unusual behavior” or sign-in from anonymized IP)."></node>
          <node TEXT="Leverage user and signin risk information in Entra sign-in logs in your detections even if you are not licensed for risk based conditional access policies for realtime enforcement."></node>
        </node>
      </node>
      <node TEXT="Entra Connect Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals can extract AD Connect credentials (it has a Get-AADIntSyncCredentials function)."></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="The adconnectdump tool by Dirk-jan Mollema is a public tool that dumps and decrypts Entra Connect's database to retrieve plaintext credentials."></node>
          <node TEXT="Attackers with admin access to the server might also use Mimikatz or custom DLL injection to extract the encrypted creds and decrypt them. Once obtained, those credentials (for on-prem AD and Entra service account) are leveraged to escalate privileges in AD or cloud."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Use a gMSA (Group Managed Service Account) for the AD DS connector account for Entra Connect, so that even if the database is stolen, the AD credential can't be easily reused outside that server."></node>
          <node TEXT="Strictly limit who can log on to or administer the AD Connect server (Tier 0 system)."></node>
          <node TEXT="Keep Entra Connect updated (to patch any known vulnerabilities in it)."></node>
          <node TEXT="If feasible, use Entra Cloud Sync (which has a lightweight agent and might reduce attack surface)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="EDR on the Entra Connect server - e.g. EDR can detect Mimikatz or DCSync behavior, possibly catching tools trying to dump the Entra Connect credentials."></node>
          <node TEXT="No dedicated Microsoft cloud tool monitors Entra Connect for credential abuse;  treat this server as a domain controller equivalent in monitoring."></node>
          <node TEXT="Entra Connect Health (while it monitors sync health) does not detect credential extraction."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Unusual behavior by the Entra Connect sync account or server."></node>
          <node TEXT="On-prem AD event logs might show the Entra Connect service account performing atypical actions (if attacker uses those creds elsewhere)."></node>
          <node TEXT="Entra audit logs could show the sync account signing in interactively (which it normally shouldn't) or changes to directory sync configuration."></node>
          <node TEXT="Gap: Extracting credentials from the AD Connect server's database or memory may not trigger any log - detection hinges on catching subsequent misuse of those creds or irregular access on the server itself."></node>
        </node>
      </node>
      <node TEXT="Redirect URL Hijack">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers often don't need a special tool - they register a malicious app in Entra and supply a redirect URI that an existing target app is vulnerable to (or an open redirect that ultimately points to them). In some cases, they exploit a vulnerable third-party app that allows arbitrary redirect URIs. Tools like custom Python scripts or Burp Suite help identify open redirect vulnerabilities, but the core of the attack is abusing legitimate OAuth behavior with cleverly chosen URLs."></node>
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Never use wildcards in redirect URIs. Register only specific, trusted redirect URLs for your apps."></node>
          <node TEXT="Implement OAuth PKCE (Proof Key for Code Exchange) for public clients - this binds the auth code to the original client, so even if an attacker hijacks a redirect and steals a code, they cannot exchange it without the code verifier."></node>
          <node TEXT="If possible, mark your app as single-tenant if it doesn't need multi-tenant access, so no one else can spoof it in another tenant."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Application Governance/Code Review - ensure all OAuth apps in the tenant (especially multi-tenant apps) have properly locked-down redirect URIs."></node>
          <node TEXT="Entra will enforce HTTPS and explicit URI matching (which helps)."></node>
          <node TEXT="A web application firewall (WAF) could mitigate some open redirect scenarios on your app domain that could facilitate this."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Notoriously hard to detect. If successfully exploited, Entra issues an auth code or token to what it believes is a valid redirect URI. There may be no obvious error - from Entra's perspective, the user authenticated to the app. Only careful review of application manifest or sign-in traces would show a token sent to an unexpected endpoint."></node>
          <node TEXT="Gap: No built-in Entra alert exists for this scenario; detection relies on catching unusual redirect URIs during app registrations or an unexpected app receiving tokens."></node>
        </node>
      </node>
      <node TEXT="Bring Your Own Vulnerable App">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
          <node TEXT="The attacker's 'tool' here might simply be an exploit script for the specific vulnerability. For example, if there's a known RCE or logic flaw in an identity provider, they'll use that."></node>
          <node TEXT="They may also use standard tools to enumerate app configuration (ROADtools to pull tenant app settings, etc.) and identify misconfigurations."></node>
          <node TEXT="Common utilities like Impacket or Postman can then be used to craft malicious SAML tokens or JWTs if the app's flaw allows it."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="atch and update all identity-related software (e.g., keep AD FS updated, apply any hotfixes for identity providers)."></node>
          <node TEXT="Decommission legacy or unnecessary authentication endpoints - for example, if an old SAML IdP or OAuth endpoint is no longer needed, remove it so it cannot be leveraged."></node>
          <node TEXT="Use defence-in-depth: even if an app is compromised, ensure that accounts have least privilege (so a flaw in an HR app's SSO can't grant global admin, for instance)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Regular penetration testing and vulnerability scanning of identity components (on-prem and cloud apps)."></node>
          <node TEXT="Some tools (Burp, ZAP) can be used on custom or third-party web apps used for SSO to catch common flaws."></node>
          <node TEXT="If the vulnerable app is a known product (e.g., an outdated AD FS or custom SAML IdP), stay abreast of vendor patches and recommendations."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Monitor for signs of known exploits being used against your SSO or identity systems (e.g., if using a third-party federated IdP, watch its logs for errors or suspicious admin actions)."></node>
          <node TEXT="Unfortunately, there's no unified log for 'someone exploited a flaw' - each app must be monitored."></node>
          <node TEXT="Gap: If an attacker exploits an unpatched vulnerability in a self-deployed identity solution (AD FS, Shibboleth, etc.), it may not be obvious except perhaps through unexpected admin changes or abnormal tokens issued."></node>
        </node>
      </node>
      <node TEXT="Dynamic Consent Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="ROADtools"></node>
          <node TEXT="There isn't a specific tool for this; attackers leverage the normal OAuth flow. For instance, using a tool like MS Graph Explorer or a custom OAuth client, an attacker controlling an app can trigger a consent screen for additional permissions (when the user is already using the app). If the user is tricked into approving, the attacker's app gets elevated access."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">          
          <node TEXT="Ideally, do not allow users to grant consent to new permissions for already-installed apps without governance."></node>
          <node TEXT="If an application needs new permissions, have an admin review and consent rather than the user doing it impulsively."></node>
          <node TEXT="Use Entra consent policy to require admin approval for any consent that includes high-privilege scopes, even if the app was previously consented for lesser scopes."></node>
          <node TEXT="Regularly review application permissions - an app that suddenly has more scopes could be a red flag."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Maester (open-source tool) can check for risky settings - for instance, it can test if users are able to consent to apps that they shouldn't, or if any apps have unreviewed permissions."></node>
          <node TEXT="Entra now also allows administrators to require re-confirmation or limit the ability for apps to request additional scopes after initial consent (through consent policies)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra audit logs will show when a user or admin grants additional permissions to an app."></node>
          <node TEXT="Incremental consent (where an OAuth app asks for new permissions on the fly) generates a new consent event."></node>
          <node TEXT="Monitoring these events, especially for privileged apps, is key."></node>
          <node TEXT="Gap: If users approve the prompt, it's a legitimate consent in Entra's view - distinguishing “dynamic consent abuse” from a normal user action is difficult without context."></node>
        </node>
      </node>
    </node>
    <node TEXT="Credential Theft">
      <node TEXT="Pass-the-Hash">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Mimikatz is the classic tool to extract NTLM hashes from memory."></node>
          <node TEXT="Pypykatz (Python variant) does similar."></node>
          <node TEXT="The Impacket toolkit's utilities (e.g., wmiexec.py, smbexec.py) allow using a stolen hash to authenticate without knowing the plaintext password."></node>
          <node TEXT="Attackers might also use built-in OS tools (like runas or wmic with appropriate flags) if they can inject the hash into a session."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Disable NTLM authentication in the domain where possible or restrict it severely (via Group Policy 'Network Security: Restrict NTLM …')"></node>
          <node TEXT="Where NTLM is needed, enforce complex passwords and frequent rotation for accounts (to limit hash validity window)."></node>
          <node TEXT="Implement unique local administrator passwords on endpoints (LAPS) so that one stolen local hash doesn't grant broad access."></node>
          <node TEXT="Ensure privileged accounts never log on to workstations, to reduce chances their hashes can be stolen."></node>
          <node TEXT="Get rid of AD!"></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Credential Guard on Windows 10/11 helps prevent hash extraction by isolating LSASS secrets."></node>
          <node TEXT="EDR can detect Mimikatz or similar tools trying to scrape hashes from memory."></node>
          <node TEXT="Additionally, Active Directory controls like SMB signing and LDAP signing make relay attacks (often paired with pass-the-hash) harder."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="AD Audit Logs: Correlate an account's NTLM logon from a new machine without prior Kerberos TGT as a 'suspected identity theft (Pass-the-Hash)'"></node>
          <node TEXT="Domain Controller security logs (Event ID 4624 with Logon Type 3 or 9) can indicate NTLM logons; if an admin account logs in via NTLM from a workstation where it normally doesn't, that's suspicious."></node>
          <node TEXT="Gap: Pure cloud environments aren't directly affected by NTLM, but hybrid attacks using on-prem hashes can indirectly impact cloud if AD is federated or synced."></node>
        </node>
      </node>
      <node TEXT="Session Cookie Theft">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Evilginx2 (and similar AiTM proxies) essentially steal session cookies."></node>
          <node TEXT="Malware on a device can directly steal browser cookies from disk."></node>
          <node TEXT="Even without specialized malware, an attacker with an existing foothold might use built-in tools: e.g., dump browser memory via debugging APIs or use JavaScript in a XSS attack to grab a session token."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Shorten session lifetimes for sensitive apps - require re-login or MFA more frequently so stolen cookies expire sooner."></node>
          <node TEXT="Use phishing-resistant MFA so even if cookies are stolen, they can't be refreshed easily (for instance, use FIDO2 which enforces re-auth on new device)."></node>
          <node TEXT="Enable Continuous Access Evaluation (CAE) - so if an anomaly is detected (account disabled, password changed, risk flagged) the session cookie's access is cut off by resources quickly."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Browser Hardening/DLP: Deploying browser isolation or at least ensuring browsers are not storing persistent session cookies unencrypted can help."></node>
          <node TEXT="Endpoint DLP or EDR can detect if cookie files are accessed in abnormal ways."></node>
          <node TEXT="Entra Conditional Access can reduce cookie reuse by setting sign-in frequency (forcing reauthentication periodically)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="CASB can detect impossible travel or session anomalies that often accompany cookie theft (e.g., a session cookie used from an unusual location triggers an alert)."></node>
          <node TEXT="Microsoft 365 Defender will raise an alert if it observes known patterns of cookie replay (for instance, via its integrations with Edge or MCAS)"></node>
          <node TEXT="Entra ID linkable Session ID (SID), which is in preview, can help incident responders connect two sign-in events with the same session cookie (one from victim's device, one from attacker's)"></node>
          <node TEXT="Gap: If an attacker uses a stolen cookie from the same general location or in a short timeframe, it may appear as a normal session; real-time detection still remains challenging."></node>
        </node>
      </node>
      <node TEXT="Pass-the-PRT">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="The attack is typically done with Mimikatz - its cloudap module can extract the PRT and session key from LSASS, and then convert them into a usable session token"></node>
          <node TEXT="AADInternals also has capabilities to request tokens given a PRT (if certain keys are known)."></node>
          <node TEXT="PowerShell script + Mimikatz to grab a PRT and then injected it into a browser session to impersonate the user."></node>
          <node TEXT="Any tool that can read LSASS memory or the TPM-protected cache (with admin rights) could potentially be leveraged to steal or use a PRT"></node>
          <node TEXT="MSAL Token cache locally on the device - not encrypted in all OS versions e.g. Linux - also Cloud Shell storage account."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Treat PRT compromise as you would a complete account takeover - so focus on prevention at the device level."></node>
          <node TEXT="Don't allow users to be local admins on their Entra-joined devices (to prevent easy PRT theft via malware)."></node>
          <node TEXT="Require compliant or hybrid-joined devices for sensitive applications; that way, a stolen PRT used from an attacker's device might fail conditional access if device compliance cannot be faked."></node>
          <node TEXT="Rotate high-risk credentials (if a PRT theft is suspected, a user password reset and invalidation of refresh tokens will invalidate the PRT chain)."></node>
          <node TEXT="Use CAE (Continuous Access Evaluation) so that certain events (user password change, device loss) invalidate the PRT and derived tokens quickly"></node>
          <node TEXT="Employee token pinning, such as Token Protection (Preview) in Entra so that tokens are cryptographically bound to the device they are generated on."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Credential Guard (on Windows) and virtualization-based security make stealing the PRT much harder (though not impossible if the attacker has SYSTEM privileges, as some attacks have shown"></node>
          <node TEXT="EDR can block or quarantine known PRT theft tools."></node>
          <node TEXT="Hardware-backed attestation for PRT (currently, PRT is bound to device and user; ensuring the device has a TPM and is managed adds protection)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="EDR may detect attempts to access the Primary Refresh Token in memory (for example, detect Mimikatz's sekurlsa::cloudap usage)"></node>
          <node TEXT="This can trigger an alert that is also fed into Entra Identity Protection as a 'Possible attempt to access Primary Refresh Token (PRT)' risk event"></node>
          <node TEXT="Entra Identity Protection by itself cannot see the theft, but it may flag downstream anomalous token usage (an 'Anomalous token' risk detection) if a PRT is replayed from an unfamiliar environment"></node>
          <node TEXT="Gap: If the attacker uses the PRT from a device that appears compliant (e.g., simulating a device join), Entra sees a normal token; direct cloud-side detection of PRT replay is extremely difficult without the endpoint signal."></node>
        </node>
      </node>
      <node TEXT="Golden SAML">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="ADFSDump (part of Mimikatz or a separate script) can extract the AD FS signing certificate and key if the attacker has admin on the AD FS server. "></node>
          <node TEXT="ADFSpoof and other custom scripts can then generate SAML tokens for any user/role."></node>
          <node TEXT="attacker might stand up a fake AD FS server with the stolen cert and use standard SAML libraries to authenticate as any user to the target service."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Secure AD FS servers as Tier 0 assets."></node>
          <node TEXT="Limit administrative access and ensure they are patched (Golden SAML itself is not a product flaw but AD FS has had vulnerabilities that facilitate certificate theft)."></node>
          <node TEXT="Regularly change the AD FS token-signing certificate (manually if not already periodically rolling) and tightly control its private key - store it on an HSM if possible"></node>
          <node TEXT="Implement additional controls like monitoring for AD FS configuration drift (any new relying party trusts or claims transformations that are unusual)."></node>
          <node TEXT="If feasible, enable Entra Conditional Access even on federated users for additional checks (like device or location filters that an attacker might trip even with a forged token)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Enable Entra Federation Health (to detect some anomalies in federation)."></node>
          <node TEXT="Enable auditing of AD FS configuration changes."></node>
          <node TEXT="Consider SolarWinds-specific detections published by Microsoft and others (like scripts to see if token signing cert was changed or additional certs were added)"></node>
          <node TEXT="Move to Pass-through Authentication/Password Hash Sync to remove AD FS if possible, or at least reduce its usage"></node>
          <node TEXT=""></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Golden SAML attack is an IdP (AD FS) issuing a token that Entra trusts - it looks like a perfectly valid federated logon."></node>
          <node TEXT="Monitor if the AD FS token-signing certificate is accessed or exported (Security Event 5136 on the AD FS container, etc.)."></node>
          <node TEXT="Gap: This technique was used in the Solorigate attack specifically because it evades cloud detection - it's extremely stealthy in Entra audit logs."></node>
        </node>
      </node>
      <node TEXT="AD CS Misconfiguration (Golden Certificate)">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Certify and Certipy are well-known tools to find and exploit AD CS flaws. They can request certificates based on misconfigured templates (e.g., a template that allows any authenticated user to enroll for a cert that has Domain Admin rights)."></node>
          <node TEXT="Once an attacker has a cert, they can use tools like Rubeus or Mimikatz to perform a Golden Ticket-like attack but with a certificate (sometimes called a 'Golden Certificate' attack, where they use the cert to sign Kerberos PAC data). Essentially, the attacker ends up with a certificate that can authenticate as a privileged user for an indefinite period."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Hardening AD CS is the primary defense: Follow Microsoft and SpecterOps guidance to fix misconfigurations - e.g., remove the ENROLL permission from vulnerable templates (like the infamous Machine* templates that allow any auth user to get a cert that could be used for domain auth)."></node>
          <node TEXT="Disable NTLM fallback on certificate auth to force strict mapping (so a cert can't be used unless explicitly mapped or issued by a trusted template)."></node>
          <node TEXT="Implement short lifetimes and publication of issued certs so they can be monitored."></node>
          <node TEXT="If possible, require multifactor for enrollment of sensitive certificates (AD CS can't natively, but you can impose out-of-band procedures for certificate requests)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Certipy (offensive tool) has a scanning mode that can be used defensively to find misconfigured templates."></node>
          <node TEXT="Locksmith tool can help apply recommended template hardening - it's more a script than a continuous tool."></node>
          <node TEXT="Enable Microsoft Defender for Identity's AD CS monitoring (a preview feature as of late 2024) if available, which can detect some certificate abuse patterns."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Active Directory Certificate Services (AD CS) events and AD events can reveal this."></node>
          <node TEXT="On the CA server, enable auditing for certificate issuance - an attacker requesting a certificate with elevated privileges (like a DC certificate or an Enrollment Agent certificate) will generate an event (e.g., Event 4886: Certificate Issued)."></node>
          <node TEXT=" if an attacker uses a forged certificate to authenticate as a domain admin (via PKINIT), the Domain Controller logs an authentication event (Event 4768) indicating certificate authentication was used for that account."></node>
          <node TEXT="MDI can sometimes detect abnormal certificate-to-account usage as part of 'PTT' detections (over-pass-the-hash scenarios)."></node>
          <node TEXT="Gap: Many orgs don't monitor their CA logs. If an attacker gets a long-lived cert for a user or even the KRBTGT account, they can silently abuse it for persistence with little trace except those initial issuance events."></node>
        </node>
      </node>
    </node>
    <node TEXT="Privilege Escalation and Lateral Movement">
      <node TEXT="Golden Ticket">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Mimikatz and Pyoykatz can craft a Golden Ticket (kerberos::golden command) given a domain's KRBTGT hash."></node>
          <node TEXT="Rubeus (C# tool) can also forge tickets and inject them."></node>
          <node TEXT="Impacket's ticketer.py is another means to create Golden Tickets (and Silver Tickets) easily."></node>
          <node TEXT="These tools allow the attacker to specify any user SID, groups (like Domain Admins SID), and a long lifetime - producing a TGT that gives them virtually unlimited access in that domain."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Regularly reset the KRBTGT account password (typically every 180 days, twice in quick succession) so that any stolen KRBTGT hash becomes unusable in a timely manner."></node>
          <node TEXT="Ensure all domain controllers are patched for known Kerberos vulnerabilities (like the ones that enable PAC spoofing - e.g., Silver Ticket related patches - these patches also help limit what a forged ticket can do)."></node>
          <node TEXT="Implement ESAE ('Red Forest') or tiered admin model so that even if a Golden Ticket is created, the accounts that can be targeted are limited (the attacker usually still needs local admin on some system to use the ticket effectively)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="There isn't a specific tool to stop Golden Tickets once an attacker has KRBTGT - it's about prevention and detection."></node>
          <node TEXT="Using MDI (Defender for Identity) as a detection tool is crucial since it has several detections for Golden Ticket (encryption downgrade, abnormal tickets, etc.). "></node>
          <node TEXT="Some third-party AD monitoring solutions (like Splunk with the right queries, or Quest Change Auditor) can catch anomalies in Kerberos tickets."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Defender for Identity reliably detects Golden Ticket usage through multiple methods - e.g., it will alert if it sees a Kerberos TGT for a nonexistent user or one with abnormal encryption (External ID 2027 alert)."></node>
          <node TEXT="Domain Controllers might log a Kerberos error if the ticket doesn't match a valid user, but in many cases Golden Tickets use valid SIDs to fly under the radar."></node>
          <node TEXT="Another indicator is a Kerberos TGT with an absurdly long lifetime (if attacker sets 10-year expiration); DCs don't normally issue those, so any such ticket in event logs is suspect."></node>
        </node>
      </node>
      <node TEXT="Silver Ticket">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Rubeus can perform Silver Ticket attacks (via asktgt/asktgs with a supplied NTLM hash of a service)."></node>
          <node TEXT="Mimikatz can forge a service ticket by using the /rc4 or /aes256 key of the service - essentially, if the attacker has an NTLM hash of, say, the MSSQL service account, Mimikatz can craft a TGS for that service marked as whatever user/permissions the attacker wants."></node>
          <node TEXT="Impacket's ticketer.py can also create TGS tickets. These forged tickets are then injected into the attacker's session to allow direct access to the target service."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Use strong, randomly set passwords for service accounts and change them frequently, or use gMSAs so that an attacker cannot maintain access with a stolen hash for long."></node>
          <node TEXT="Avoid using one service account for many applications - segmentation limits impact."></node>
          <node TEXT="You can also enable “Audit Kerberos Service Ticket Operations” on domain controllers, which might log events if a TGS is requested with unusual flags (though a Silver Ticket might not request one at all)."></node>
          <node TEXT="Ensure your domain controllers are patched for the S4U2Self delegation issues that could be combined with Silver Tickets."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Similar to Golden Ticket, no tool can outright prevent a forged ticket if the attacker has the service account's key. Monitoring tools (MDI, SIEM correlation) are key to detection."></node>
          <node TEXT="To prevent, focus on reducing attack surface: gMSA (Group Managed Service Accounts) for services automatically change the account's password regularly (limiting how long a stolen hash is useful)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Also, a target server (e.g., a SQL server) might log an authentication event that did not involve a DC - that by itself is hard to catch centrally. Correlating server logon events with absence of DC ticket issuance could indicate Silver Ticket use.
"></node>
          <node TEXT="Defender for Identity will detect pass-the-ticket attacks; a Silver Ticket is essentially a forged service ticket (TGS) used directly on a service. One clue is an account using a service without the usual preceding TGT request - MDI's “Suspected Pass-the-Ticket” alert (external ID 2018) triggers when it sees the same TGS used on two machines without a corresponding AS-REQ【26†L173-L182】."></node>
        </node>
      </node>
      <node TEXT="Certificate Based Authentication Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals"></node>
          <node TEXT="An attacker who compromises a corporate CA or template can issue themselves a certificate for a target user."></node>
          <node TEXT="Tools like Certipy can request a certificate as that user (if template allows) and then the attacker can use standard Windows tools to import and use that cert for authentication."></node>
          <node TEXT="AADInternals could potentially add a certificate credential to a user via Graph API (if the attacker has sufficient privilege) - abusing the upcoming certificate authentication feature."></node>
          <node TEXT="In federated setups, an attacker with a cert and access to the network can simply run klist or certutil to import it and authenticate via AD FS or Kerberos with it - no special malware required, just the cert and private key."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Lock down certificate authorities (CAs) - ensure your enterprise CA is well secured, and templates that map to user authentication are hardened (overlap with AD CS misconfig hardening)."></node>
          <node TEXT="In Entra ID, upload only your trusted root CA for CBA and optionally require user certificate mappings (UPN or object SID in cert must match the user) so an attacker can't use a cert unless it's truly issued to that user."></node>
          <node TEXT="Monitor for any new certificate added to a user's “Authentication Methods” (if using cloud cert auth, an admin might add a cert for a user - that should be rare)."></node>
          <node TEXT="For federated scenarios, disallow alternative certificate login methods like NTLM fallback on AD FS - require the cert if that factor is needed."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Azure AD Certificate-Based Authentication (CBA) preview - allows you to enforce which users can use cert auth and what CAs are trusted. Use this to only trust your organization's smartcard/PKI."></node>
          <node TEXT="If using AD FS, ensure Extended Protection for Authentication is enabled and consider certificate authentication policies."></node>
          <node TEXT="Conditional Access can also be configured to require MFA even if a certificate is presented, for critical accounts (to prevent an attacker from leveraging only a stolen cert).
"></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Azure AD sign-in logs will show “Authentication method: Certificate” when a user authenticates with a certificate (either via Azure AD CBA or federation)."></node>
          <node TEXT="Watch for users who normally don't use certificate auth suddenly doing so."></node>
          <node TEXT="In on-prem AD, if an attacker uses a certificate to authenticate (e.g., via AD FS or Kerberos PKINIT), you'll see events on domain controllers (4768 with “Certificate Issuance” or “Certificate Mapping”)."></node>
          <node TEXT="If AD FS is used, it might log ID 501 indicating certificate authentication."></node>
          <node TEXT="Gap: A valid certificate login is usually not flagged as suspicious by itself - detection requires noticing the certificate was not one normally associated with the user or issued by an unexpected CA."></node>
        </node>
      </node>
      <node TEXT="OAuth Token Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers with a stolen token often use scripts or legitimate tools to impersonate the user. For instance, with a stolen access token, an attacker can call APIs directly via tools like Postman or curl."></node>
          <node TEXT="With a stolen refresh token, they can use libraries or tools (like custom Python scripts using MSAL) to redeem it for new access tokens for various services."></node>
          <node TEXT="There have been community tools (like Proof-of-Concept scripts from Dirk-jan) demonstrating how to replay a refresh token to obtain a Graph token and read mail, etc. Essentially, once tokens are stolen, any tool that can craft HTTP requests to Entra and resource endpoints becomes an attacker's tool."></node>
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Short token lifetime and forced reauth - although modern default access tokens are ~1 hour and refresh tokens can live 90 days, you can reduce these or enforce re-login after e.g. 12 hours for sensitive apps."></node>
          <node TEXT="Use Conditional Access device compliance or managed device requirements so that even if tokens are stolen, they can't be reused from an untrusted device (because the device claim would be missing)."></node>
          <node TEXT="Monitor consent to any application that has high privileges - an attacker might abuse a token via a malicious app, so controlling app consent (as discussed above) helps here too."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Entra Conditional Access with session controls - you can set sign-in frequency so that long-lived refresh tokens are less of an issue."></node>
          <node TEXT="Also, enabling Continuous Access Evaluation (CAE) on supported apps will make refresh tokens and even access tokens revocable on certain events (like password change, account disable, or high risk)."></node>
          <node TEXT="Privileged Identity Management (PIM) can limit how long a privileged role token is valid by requiring time-bound role activation (so even if an attacker steals a global admin's token, that token might not have GA rights if PIM wasn't activated at that moment)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="This often refers to using stolen access/refresh tokens to access resources illicitly. Identity Protection's 'Anomalous Token' detection can catch unusual token characteristics or reuse (for example, a refresh token used from an unfamiliar environment or an impossible token lifetime)."></node>
          <node TEXT="CASB can detect if a token is used from two far apart locations in a short time (implying theft)."></node>
          <node TEXT="Additionally, Microsoft Graph API logs (if collected) could show an application or user suddenly performing high-privilege operations (like adding roles) which might indicate a stolen token being wielded by an attacker."></node>
        </node>
      </node>
      <node TEXT="1st Party App Consent Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Family Of Client IDs (FOCI)">
            <node TEXT="An attacker who has a refresh token can attempt to use it to get tokens for other apps in the family."></node>
            <node TEXT="They might use MSAL in PowerShell or Python to do this (by specifying the client ID of another app when redeeming the refresh token). For example, using a stolen refresh token from Teams to get an Outlook token via a script."></node>
            <node TEXT="Tools like ROADtools or custom code can automate extraction and reuse of such tokens. Essentially, the attacker leverages Microsoft's own token service - no special exploit code beyond knowing how to craft token requests."></node>
          </node>
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Treat sessions on first-party clients as you would any other - enforce MFA and device requirements so that even if an attacker gets a token through FOCI, they can't use it from an untrusted context."></node>
          <node TEXT="Keep an eye on accounts with high privileges - if they are enabled for FOCI (which they are by default), be aware that a compromise of any one session (even a low-privileged app) can potentially be leveraged to access data from another."></node>
          <node TEXT="You might reduce the attack surface by disabling legacy clients and older protocols where possible."></node>
          <node TEXT="Unfortunately, FOCI is an inherent behavior, so it comes back to catching the token theft in the first place. Also consider that it may not be a stolen token, it could be a malicious insider."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="There's not a specific control to turn off FOCI (it's by design for Microsoft apps)."></node>
          <node TEXT="However, Continuous Access Evaluation can mitigate some risk by ensuring that even FOCI tokens are re-evaluated on certain events."></node>
          <node TEXT="Also, consider using Conditional Access to require fresh authentication for critical apps like Exchange Online if risk is detected (though this is reactive)."></node>
          <node TEXT="Monitoring via CASB of sessions that change user agents could help."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="This refers to abusing the Family of Client IDs (FOCI) - using a refresh token from one first-party app to access another first-party app."></node>
          <node TEXT="It's tricky to detect; Entra may log an access as coming from, say, 'Outlook' when the token originally came from 'Teams'."></node>
          <node TEXT="Identity Protection's anomalous token detection might flag this if the usage is abnormal."></node>
          <node TEXT="Also, if an attacker uses a FOCI token to access Exchange Online, there might be an unusual pattern like a token for 'OneDrive' being used to call Exchange - these subtleties could surface in advanced audit data (Microsoft 365 audit logs)."></node>
        </node>
      </node>
      <node TEXT="Azure RBAC Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers often just use Azure's own tools: Azure CLI (az) or Az PowerShell module to enumerate roles and assign themselves or their backdoor identities to roles."></node>
          <node TEXT="For example, with a compromised credential, an attacker might run az role assignment create --assignee {attackerPrincipal} --role Owner --scope {subscription} - a legitimate command, but malicious intent."></node>
          <node TEXT="There are also post-exploitation toolkits (like PowerZure or Stormspotter combined with BloodHound data) that help find and exploit over-privileged Azure roles, but a simple CLI is often enough."></node>
          <node TEXT=""></node>
          <node TEXT=""></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Segregation of duties - don't give application identities overly broad RBAC roles; limit what each admin can do."></node>
          <node TEXT="Use custom roles to limit scope."></node>
          <node TEXT="Implement an alert or even an automation (via Logic App) to flag and optionally revert if an excessive role is granted."></node>
          <node TEXT="Regularly review Azure RBAC assignments (who has Owner on subscriptions, etc.) and remove unnecessary ones (use Access Reviews for Azure resources if available)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Azure Privileged Identity Management (PIM) for Azure RBAC - require just-in-time activation for roles like Owner or Contributor, with approval. That way, even if an attacker gets a Global Admin, they would also need to activate a separate Azure role (or compromise an eligible admin) to make permanent changes."></node>
          <node TEXT="Also, Azure Policy can enforce restrictions (for instance, a policy that there must be at least two owners - which might help catch removal of legitimate owners)."></node>
          <node TEXT="Using Management Groups with centralized control can make it easier to monitor changes across subscriptions."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Azure Activity Logs are the primary source - any role assignment changes (e.g., adding a user as Owner to a subscription, or adding a service principal to a role) are logged. Setting up alerts on these, especially for Owner/Contributor on subscriptions or Resource Group level, is critical."></node>
          <node TEXT="Entra Audit Logs will show directory role changes (though Azure RBAC roles are separate and found in activity logs)."></node>
          <node TEXT="If an attacker uses stolen credentials to perform actions, you might also see unusual operations in resource logs (like VMs created by an unexpected user)."></node>
        </node>
      </node>
      <node TEXT="T0 Equivalent API Permissions Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="An attacker who gains the credentials of an app with T0 permissions (like a client secret or certificate for an app with User.ReadWrite.All or RoleManagement.ReadWrite.Directory) can use any standard Graph client to do damage."></node>
          <node TEXT="For example, they could use Microsoft Graph Explorer (by authorizing it with the stolen app creds) or simply craft HTTP requests with curl including the stolen token."></node>
          <node TEXT="No special 'attack tool' is needed beyond understanding Entra and Graph. In some cases, attackers create their own Entra app and grant it these permissions (if they have admin rights), then use Graph API to backdoor the tenant - essentially using Entra as the tool against itself."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Maester"></node>
          <node TEXT="Restrict and Audit Use of Scopes">
            <node TEXT="Directory.ReadWrite.All"></node>
            <node TEXT="RoleManagement.ReadWrite.Directory"></node>
            <node TEXT="AppRoleAssignment.ReadWrite.All"></node>
            <node TEXT="UserAuthenticationMethod.ReadWrite.All (FIDO2/TAP Only)"></node>
          </node>
          <node TEXT="If some third-party product demands an excessive permission, push back or monitor it heavily."></node>
          <node TEXT="Periodically review all Enterprise Applications for any with these powerful permissions"></node>
        </node> 
        <node TEXT="Preventative Tools">
          <node TEXT="Admin Consent Workflow - ensure any request for highly privileged OAuth scopes triggers a process (Entra's built-in workflow for admin consent requests can be used, or a manual review)."></node>
          <node TEXT="Identity Governance solutions can enumerate who/what has powerful API permissions (for instance, Cloud App Security's App Governance add-on can identify apps with 'read all' or 'write all' directory permissions)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Audit Logs will show when an application is granted a high-privilege Graph permission (like Directory.ReadWrite.All, which is effectively tenant admin)."></node>
          <node TEXT="Monitor admin consent events closely: granting of these T0-level permissions should be rare and is auditable."></node>
          <node TEXT="Also, Microsoft Graph Activity logs (if collected) could reveal an application using those permissions (e.g., an app suddenly creating users or adding directory roles)."></node>
          <node TEXT="Gap: If an attacker already has an app with such permissions, every use of them will look like normal API calls. It requires knowing which apps have these permissions and watching their activity (perhaps via SIEM alerts on certain app IDs invoking sensitive APIs)."></node>
        </node>
      </node>
      <node TEXT="OverPermissioned Application Scopes">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers will search for apps that have high privileges. They might use AADInternals or Entra PowerShell to list all service principals and their OAuth2Permission grants."></node>
          <node TEXT="Once they find an app with a juicy permission (like an app with Mail.Read for all mailboxes), they'll try to obtain its credentials - via phishing a dev, searching code repositories for client secrets, or abusing an insecure configuration (like the 'Hidden client secret' issue)."></node>
          <node TEXT="If they get the credentials, using them is trivial with normal Graph queries. Essentially, the 'tool' here is often just PowerShell or a programming script using the stolen app credentials to perform actions under the app's identity."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Enforce least privilege on application permissions - when developers register apps, have a process to approve the requested scopes."></node>
          <node TEXT="Remove any granted API permission that is no longer needed."></node>
          <node TEXT="If an application was granted, say, full mailbox access during testing and not removed, that's a latent risk - clean it up."></node>
          <node TEXT="Enable Verified Publisher requirements (apps published by your org can then be more trusted, others get limited) to reduce risk from rogue apps."></node>
          <node TEXT="Also consider requiring user assignment for enterprise apps - that way even if an app has a broad permission, only specific accounts can use it."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Governance/Compliance Reviews - use scripts or tools to regularly dump all app permissions in the tenant and flag those that are high privilege."></node>
          <node TEXT="Microsoft Cloud App Security's App Governance module can automatically flag over-permissioned apps and even suspend them."></node>
          <node TEXT="Third-party IAM governance tools can also do periodic least-privilege analysis."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="This scenario is about applications that have more permissions than they actually need - an attacker might target those apps."></node>
          <node TEXT="Defender for Cloud Apps - App Governance (if available) can highlight OAuth apps that have excessive permissions or anomalous behavior."></node>
          <node TEXT="Without that, detection falls to admin review: Entra's portal lists all permissions an app has; any app with broad read/write permissions to data it shouldn't need should be questioned."></node>
          <node TEXT="Also, the service principal sign-in logs (now available in Entra ID) show what an app is doing - seeing a low-use app suddenly performing high-impact actions could indicate abuse."></node>
        </node>
      </node>
    </node>
    <node TEXT="Persistence">
      <node TEXT="Adding Rogue Federation Trusts">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers with GA rights can use PowerShell (MSOnline or AzureAD module) to add a domain (New-MsolDomain) and then set federation (Set-MsolDomainAuthentication)."></node>
          <node TEXT="AADInternals"></node>
          <node TEXT="AADInternals can also automate adding a federated domain. They will use a domain they control, set up their own AD FS or STS, and establish trust so that they can issue tokens for your tenant. This is essentially abusing Entra's normal domain federation mechanism."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Limit who can add domains - only Global Admins can, so keep GA count minimal and highly secure (MFA, privileged access workstations)."></node>
          <node TEXT="Regularly review verified domains in your tenant; any unknown domain should be removed immediately."></node>
          <node TEXT="If possible, use Privileged Identity Management to make Global Admin role eligible and not permanent, so an attacker who gets a lesser admin account can't immediately elevate to GA and add domains (this is more about slowing down attacks)."></node>
          <node TEXT="In an ideal scenario, set up an alert or approver requirement for adding federations (though Entra doesn't have a native feature for this, an organizational process can be put in place)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="There's no built-in alert for domain additions, so a custom monitoring solution is needed - e.g., use Azure Monitor or a Logic App to watch the audit log. Entra now has an option to require additional approval for critical changes (via Privileged Access), but domain addition isn't individually protected out-of-the-box."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Audit Logs will log if a new domain is added to the tenant, and whether it's set as federated (including the federation metadata URL)."></node>
          <node TEXT="This is a key indicator - for example, an attacker adds 'rogue.com' and sets up federation, there will be audit events."></node>
          <node TEXT="Monitoring for any changes to domain federation settings (New federation trust or modifications to existing) is essential."></node>
          <node TEXT="Additionally, if an attacker actually uses the rogue domain to log in, you'd see sign-ins for an account in that domain - which might look odd in logs (e.g., 'user@rogue.com' signing in)."></node>
        </node>
      </node>
      <node TEXT="OAuth App Consent Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT=" MicroBurst (PowerShell toolkit) has scripts to create stealthy Azure backdoors - e.g., registering an app and adding credentials and permissions without raising UI prompts."></node>
          <node TEXT=" An attacker with sufficient permissions might just use AzureAD PowerShell: New-AzureADApplication, New-AzureADServicePrincipal, then New-AzureADServiceAppRoleAssignment to grant it rights. All of these are legitimate commands."></node>
          <node TEXT="They could also modify an existing application (if they compromise something like an automation account's app) by adding a new secret - that's the 'hidden client secret' style persistence."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Disable 'Users can register applications' if not needed (so only admins can create apps). This prevents a standard user from creating a backdoor app - in persistence scenario, it's usually a compromised admin doing it, but removing general ability reduces noise."></node>
          <node TEXT="Use Conditional Access to block legacy auth and enforce MFA - not directly related to apps, but ensures an attacker can't just use the app's credentials without MFA if they attempt to interact as a user."></node>
          <node TEXT="Regularly review apps and service principals in your tenant; any unfamiliar application (especially if created by a regular user account or recently by an admin who doesn't typically do that) should be scrutinized."></node>
          <node TEXT="Remove redundant admin consent grants (attackers have been known to leave behind an app with client_credentials flow and Global Reader-type permissions as a backdoor)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Use Entra Governance features: for example, enable a process where any new enterprise application with high privileges triggers an admin review."></node>
          <node TEXT="Continuously run Maester or similar to identify risky configurations (Maester's tests can flag if an app has too many privileges or if user consent is enabled when it shouldn't be)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Similar to initial access consent phishing, but here the attacker (already with admin rights) might register a clandestine app or modify an existing one."></node>
          <node TEXT="Audit logs will show if a new app is created or if an admin grants consent on behalf of the org to an app."></node>
          <node TEXT="Also, watch for new credentials added to apps (audit event 'Add credential to application' could indicate backdoor client secrets)."></node>
          <node TEXT="Defender for Cloud Apps can sometimes catch if an app starts doing abnormal things (multiple users' data accessed by an app that wasn't seen before)."></node>
          <node TEXT=""></node>
        </node>
      </node>
      <node TEXT="MFA Fatigue">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="The attacker doesn't need special tools beyond a script or macro to continuously attempt logins. For instance, they can use while(true) loop with curl or PowerShell invoking the OIDC auth endpoint to trigger MFA each time."></node>
          <node TEXT="For instance, they can use while(true) loop with curl or PowerShell invoking the OIDC auth endpoint to trigger MFA each time. Some attack frameworks incorporate MFA fatigue modules (e.g., there are tools that integrate with Microsoft's APIs to push Authenticator notifications repeatedly)."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="MFA configuration: Require users to use Authenticator app or security keys rather than SMS/voice (those tend to have no 'accept/deny' prompt, but an attacker can still spam phone calls)."></node>
          <node TEXT="Set up a policy such that after X failed MFA attempts in Y minutes, the account is temporarily suspended or requires admin intervention - this isn't native in Entra, but you might achieve it via conditional access (e.g., if risk level rises due to many failures)."></node>
          <node TEXT="Encourage users to utilize passwordless authentication (like FIDO2 keys), which don't have an 'approve' prompt that can be fatigued - they require a physical action on a device."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Microsoft has now enabled Number Matching and Additional Context in Authenticator by default - these are preventative because they make it far less likely a user will blindly approve. Ensure these features are enabled for all users (as of 2023, Microsoft enforced number matching globally)."></node>
          <node TEXT="User training is a non-technical but absolutely vital tool - users must know to report unexpected prompts rather than approve them."></node>
          <node TEXT="Some organizations deploy third-party MFA fatigue detection plugins or scripts (for example, using the Microsoft Graph API to monitor if a user has many MFA denials and then temporarily blocking login or forcing password reset)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra sign-in logs do record MFA challenge results. If a user's account shows dozens of consecutive MFA prompts (authentication attempts marked 'MFA denied') in a short span, this is a clear indicator of an MFA fatigue attack."></node>
          <node TEXT="While there isn't an out-of-the-box alert solely for that, a custom rule or Microsoft Sentinel query can detect it."></node>
          <node TEXT="Also, user reports are critical - users often notify IT of 'getting bombarded by MFA prompts,' which should be treated as an incident."></node>
          <node TEXT="Gap: Historically, Identity Protection didn't explicitly flag 'MFA spam,' especially if the user eventually approves (that would just look like a successful MFA). The new Authenticator features (number matching) reduce success, so detection needs might diminish as success rates drop."></node>
        </node>
      </node>
      <node TEXT="Hidden Client Secrets (App Reg - API only CRUD)">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="An attacker with appropriate permissions can use Azure AD Graph API (or MS Graph) to add a credential."></node>
          <node TEXT="For instance, using AADInternals, an attacker could call New-AADIntServicePrincipalKey to insert a new client secret into an app."></node>
          <node TEXT="Or use raw Graph calls: POST to /servicePrincipals/{id}/addPassword. These secrets won't show up in the portal immediately (in older Entra behavior), allowing stealth."></node>
          <node TEXT="Once added, the attacker can use standard tools (Azure CLI, etc.) with that client secret to authenticate as the app."></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Least privilege for app management - only a small number of administrators (e.g., Application Admins) should be able to add credentials to apps."></node>
          <node TEXT="Remove the ability for application owners to independently add credentials once an app is initially configured (not directly possible as a setting, but you can control who has write access to the app object)."></node>
          <node TEXT="Also, if an application is sensitive, consider using certificates (stored in Key Vault with monitoring) instead of client secrets; certificates are harder to add unnoticed (and usually require more steps)."></node>
          <node TEXT="Turn on Entra logging to an external SIEM so that even if an attacker hides a secret, the event of creation is recorded externally."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Utilize PowerShell/Graph to enumerate app credentials periodically and compare against what is expected. For example, run Get-AzureADServicePrincipal -All $true | Get-AzureADServicePrincipalCredential to list credentials - catch any unknown client secrets."></node>
          <node TEXT="Set up alerts on audit events for app credential additions."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Audit Logs will show if someone added a client secret or key to an application (e.g., an event 'ServicePrincipalCredentialAdded')."></node>
          <node TEXT="This is often how hidden secrets come to be - via Graph API or PowerShell, an attacker adds a credential that isn't obvious in the GUI."></node>
          <node TEXT="Regularly review the audit log for such entries, especially for important apps."></node>
          <node TEXT="Also, if an app that historically used certificates suddenly gets a client secret added, that's a red flag."></node>
          <node TEXT="Gap: The Azure portal might not show these 'API-only' added credentials (hence 'hidden'). Thus, relying on portal view can mislead admins into thinking an app has no credentials when it actually does in the backend. Only the audit trail or direct Graph queries reveal them."></node>
        </node>
      </node>
      <node TEXT="User Managed Identity Federation">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="An attacker can use Azure CLI or Graph API to add a federated credential to an app."></node>
          <node TEXT="For example, az identity federated-credential create (if such command exists) or the equivalent Graph call."></node>
          <node TEXT="ROADtools/ROADrecon could likely enumerate such credentials once set."></node>
          <node TEXT="There was also a known case of attackers abusing Automation Account managed identities via Azure federation - they essentially create their own IdP token to impersonate an Azure identity. The tools are basically the Azure APIs themselves; it's a configuration abuse."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Disable user app registrations (again, so only admins can set up federations)."></node>
          <node TEXT="Limit which identities can create service principal federations - only the application's owner or a specific admin role should have that ability."></node>
          <node TEXT="Treat any configuration of federation as a change requiring security review."></node>
          <node TEXT=" If not using the feature, periodically run a script to ensure no service principals have FederatedIdentityCredentials set."></node>
          <node TEXT="Additionally, naming conventions: any legitimate federation (e.g., for GitHub Actions) should be documented; if you find one that isn't, that's suspicious."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Entra Workload Identity Federation settings - use them intentionally so you know exactly which apps have federations configured."></node>
          <node TEXT="There's currently no tenant-wide switch to disable this feature (aside from not assigning the roles that allow managing it)."></node>
          <node TEXT="Leverage Conditional Access if possible: e.g., require that service principal sign-ins come from trusted networks (not commonly done, but possible with workload identities conditions in preview)."></node>
          <node TEXT="Also, a SIEM can parse audit logs for the keywords related to federated identity addition."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Check Entra Audit Logs for any addition of a federated identity credential on service principals. This is a newer feature (Workload Identities federation) that allows linking an external IdP token to an Entra app."></node>
          <node TEXT="If an attacker sets up, say, an AWS or GitHub federation on a service principal, the audit log will show an entry."></node>
          <node TEXT="Also, monitor token issuances - if you see sign-ins by an app where the authentication method is 'Federated' (with an external issuer claim), that indicates a token was accepted via this route."></node>
          <node TEXT="Gap: Because this is relatively new, many orgs might not be monitoring it at all. A malicious federation could fly under the radar if audit logs aren't reviewed."></node>
        </node>
      </node>
      <node TEXT="Refresh Token Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers with a refresh token can use toolsets like TokenTactics (which includes functions to convert refresh tokens to access tokens for various services)."></node>
          <node TEXT="Alternatively, they might script against the OAuth token endpoint directly. One could even use Postman: import the refresh token and client ID and hit the token endpoint to get new tokens (it's that straightforward)."></node>
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Shorten the refresh token lifetime for certain scenarios - by default it's long-lived, but Conditional Access can set sign-in frequency that indirectly forces reauthentication, invalidating the refresh token more often."></node>
          <node TEXT="Implement step-up authentication: for sensitive actions, require the user to enter credentials or MFA again, so a thief with only the refresh token can't perform those without additional interaction."></node>
          <node TEXT="Educate users and admins that credentials aren't the only things to guard - sessions (like leaving a device unlocked, or tokens in device storage) are sensitive."></node>
          <node TEXT="On high-risk user detection, use an auto-remediation policy to revoke sessions (Entra has a one-click 'Revoke all sessions' which invalidates refresh tokens)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Continuous Access Evaluation (CAE) - ensures certain critical events (password change, account disable, high risk detected) revoke the refresh token's validity quickly, thereby limiting how long a stolen refresh token can be abused."></node>
          <node TEXT="Also, Identity Protection risk-based policies can force a password reset or MFA re-registration if a risky sign-in (possibly from refresh token abuse) is detected, which in turn invalidates refresh tokens."></node>
          <node TEXT="Using a CASB like Defender for Cloud Apps session management, one could cut off OAuth sessions when suspicious (though primarily for web sessions)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Identity Protection has an 'Anomalous Token' detection which often signals refresh token misuse - e.g., a refresh token replayed from a new location, or an irregular token lifetime was observed. This is an offline detection that would flag the user's risk to 'High'."></node>
          <node TEXT="Additionally, if the attacker uses a refresh token to get access tokens for multiple resources, you might see a cluster of sign-ins for different apps in a short time from the same IP - an unusual burst that could be caught via SIEM analytics."></node>
          <node TEXT="The new linkable identifier features (SID and UTI) help connect an access token back to the parent refresh token/session, so investigators can see the full chain of token usage"></node>
        </node>
      </node>
      <node TEXT="Temporary Access Pass Abuse">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="There's no public 'exploit' tool for TAP since it's a feature - the 'tool' is simply having the right admin privileges. An attacker with Authentication Administrator or Global Admin can use Entra PowerShell (New-AzureADMSInvitation or the Graph API endpoint for TAP) or even the Entra portal to create a TAP for an account."></node>
          <node TEXT="One could script the Graph REST call to generate a TAP and then use that code to authenticate via web or MSAL. For example, Dirk-jan's ROADrecon might enumerate TAP info, but creation still requires roles."></node>
          <node TEXT="Essentially, if an attacker gets the keys to do this, they can just leverage Microsoft's APIs directly to generate and use a Temporary Access Pass."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Limit TAP issuance - only a very small number of people (e.g., helpdesk in a controlled workflow) should be able to issue Temporary Access Passes, and only for onboarding or recovery scenarios."></node>
          <node TEXT="Use policies to enforce TAP being one-time use and short-lived (TAP can be configured to expire in minutes/hours)."></node>
          <node TEXT="If a TAP is issued, ideally the user should be forced to register a stronger auth method immediately, consuming the TAP."></node>
          <node TEXT="Also, treat TAP like a credential - if an admin generates one, have a secondary approval (could be a manual process: e.g., 2nd admin must inform or oversee)."></node>
          <node TEXT="Log all TAP creations and do after-action reviews to confirm they were legitimate."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Authentication Methods Policy (in preview) allows fine control over TAP - for instance, you can disable TAP for admin accounts, or require certain conditions for its use."></node>
          <node TEXT="Implement this to reduce who can use TAP. No open-source tool here; rely on Entra's built-in settings."></node>
          <node TEXT="Additionally, Privileged Identity Management for the Authentication Admin role can ensure only approved individuals can generate TAPs and only when necessary."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Audit Logs in Entra ID show TAP lifecycle events - creation, activation, and redemption of Temporary Access Pass codes."></node>
          <node TEXT="If an attacker maliciously creates a TAP for an account (requires Authentication Administrator or similar role), that event is recorded ('Temporary Access Pass created for [user]')."></node>
          <node TEXT="Monitoring those events, especially for privileged accounts or by unexpected admins, is crucial."></node>
          <node TEXT="Also, sign-in logs will indicate if a TAP was used as the authentication method for a sign-in (look for authentication detail = Temporary Access Pass)."></node>
        </node>
      </node>
    </node>
    <node TEXT="Evasion">
      <node TEXT="MFA Fatigue">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Simple scripts or repeated login attempts. Attackers have also used scheduling: attempting logins at late hours to catch users off-guard. No special toolkit needed, making this tough - it's more a technique than a tool-driven attack."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="User training and possibly policies to lock account after X MFA failures. Microsoft also rolled out features like 'MFA fraud alert' - if a user reports 'deny' with code, it can automatically disable account or escalate. Encourage use of that feature via user education."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Number matching and additional context have largely mitigated this by requiring user interaction that can't be 'fatigued' blindly. Ensuring these are enabled is key."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="(See same technique in Persistence for details) - multiple MFA denials in logs. Entra now can flag unusual sign-in behavior but dedicated detection might require custom rules. If eventually the user gives in, the successful sign-in might be marked 'Compromised' later by Identity Protection after correlation."></node>
        </node>
      </node>
      <node TEXT="ROPC (Legacy Auth Exploitation - No MFA)">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers may use MSAL or ADAL libraries in a script to attempt ROPC. For instance, a Python script with MSAL can take a list of usernames and a password to try ROPC login to Entra."></node>
          <node TEXT="Tools like MailSniper had modes to attempt ROPC for O365 as well (username/password guessing)."></node>
          <node TEXT="Essentially, any tool designed to test credentials could implement ROPC to bypass MFA - because if successful, it yields an access token. Even Postman or curl can be used to craft an ROPC token request to the /token endpoint."></node>
          <node TEXT="AADInternals"></node>
          <node TEXT="ROADtools"></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph"></node>
          <node TEXT="Azure AD Graph"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Disable ROPC on app registrations - by default, Entra allows public client flows (which include ROPC) for native apps unless explicitly turned off."></node>
          <node TEXT="Go through your enterprise apps and ensure 'allow public client flows' is set to No unless needed."></node>
          <node TEXT="Prefer modern auth methods: make sure none of your critical workflows rely on ROPC. If they do, move them to interactive flows or device code with MFA."></node>
          <node TEXT="Also, as part of legacy auth disablement, note that while ROPC is technically modern OAuth, it behaves like legacy from an MFA perspective, so treat it similarly and block it."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Conditional Access now has an 'Authentication flow' condition where you can block Resource Owner Password Credentials flow specifically. Implement that if you have no dependency on ROPC."></node>
          <node TEXT="Also, ensure security defaults or MFA policies are in place - ROPC is disallowed when MFA is enforced (because it can't perform MFA, the attempt fails if MFA is required)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra sign-in logs clearly label the authentication method. If an OAuth2 token request used grant_type=password (ROPC flow), the 'Client App' field might show as 'Legacy Authentication' or specifically 'Unknown client' with a resource - it's identifiable."></node>
          <node TEXT="You can filter sign-ins by 'Authentication requirement: single-factor' to catch ROPC usage, since it bypasses MFA."></node>
          <node TEXT="Identity Protection might increase risk for users who successfully log in without MFA from unusual locations."></node>
        </node>
      </node>
      <node TEXT="Fake MFA">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="External Authentication Methods">
            <node TEXT="One hypothetical method: an attacker with AD FS control could set the AuthenticationMethodsReferences in a SAML token to 'MFA' even if second factor wasn't performed - Entra would trust it if the federation is configured to pass through MFA claims."></node>
            <node TEXT="This is more a configuration exploit than a toolkit. Tools like ROADoidc indicate research into forging external IdP responses - an attacker could potentially use it to simulate an OAuth OIDC response that Entra accepts as MFA (though this is quite complex)."></node>
            <node TEXT="Another angle is the 'silver ticket' approach mentioned: using a Silver Ticket to impersonate the Azure MFA adapter on AD FS."></node>
          </node> 
          <node TEXT="Silver Ticket"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Don't allow weak external MFA - for instance, if Entra is configured to accept MFA from AD FS, ensure AD FS itself requires a strong method."></node>
          <node TEXT="Lock down who can modify claim rules on AD FS (only domain admins effectively)."></node>
          <node TEXT="If 'Alternate login methodologies' (like custom MFA via graph API) are in preview, restrict their use."></node>
          <node TEXT="Essentially, to prevent 'fake MFA,' one must eliminate opportunities where the system accepts an assertion of MFA that an attacker could generate."></node>
          <node TEXT="In cloud-only, that's hard without compromising keys (which falls back to Golden SAML or token forgery detection)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="If using third-party MFA integration (custom controls, AD FS adapter, etc.), ensure those systems have their own alerts when unusual events happen (e.g., if the third-party MFA is bypassed or put in 'override' mode)."></node>
          <node TEXT="Entra now allows some external IdPs for MFA - monitor if any are configured unexpectedly."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="If an attacker manages to fake an MFA (for instance, by exploiting a weakness in an external MFA provider or tricking the system into thinking MFA was done), detection is difficult."></node>
          <node TEXT="Entra sign-in logs would show 'MFA satisfied by claim' or 'external provider' - if you know that a given user shouldn't be using an external MFA, that's a sign of compromise."></node>
          <node TEXT="For example, seeing 'Duo' as MFA for a user who shouldn't have it."></node>
          <node TEXT="Gap: Many such evasion techniques involve exploiting the integration points (like modifying claims via a Silver Ticket on AD FS to add 'MFA done'). Those would appear as normal successful MFA in logs."></node>
        </node>
      </node>
      <node TEXT="Fake Compliant Device">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="In one AADInternals blog, Dr. Nestori mentioned making a device 'compliant' by manipulating Entra device registration and Intune data."></node>
          <node TEXT="An attacker with Intune admin API access might script setting an arbitrary device record's compliance to true."></node>
          <node TEXT="Alternatively, if they have the device's Entra device key, they might replay it."></node>
          <node TEXT="However, there's no off-the-shelf tool publicly known to generically fake compliance; it likely requires using Graph API calls with high privilege (essentially, an Intune admin 'rubber stamping' the device). So, the 'tool' is the Intune Graph API and the attacker's privileges."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Use Device Attestation (if available with your devices) - this ensures the device that reports compliance can present cryptographic proof of its identity and state."></node>
          <node TEXT="Entra and Intune have preview features for attestation from certain platforms."></node>
          <node TEXT="Also, tie compliance to specific checks that are hard to spoof remotely (like presence of certain software, or a compliance policy that requires an immutable custom attribute only real devices have)."></node>
          <node TEXT="Moreover, require either Hybrid AD Join or device certificate in addition to compliance for critical apps - an attacker may fake one aspect but unlikely to fake being domain-joined with a valid certificate."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Defender for Endpoint's device risk can supplement compliance - for example, you can require not just compliance but also 'device risk = low' in Conditional Access."></node>
          <node TEXT="If an attacker somehow got a device marked compliant in Intune without actually having the device secure, they likely wouldn't have the MDE sensor on it reporting risk."></node>
          <node TEXT="Using multiple signals (compliance + MDE risk or compliance + domain join) helps."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="This is when an attacker tricks Entra into thinking an unmanaged device is compliant (to bypass conditional access)."></node>
          <node TEXT="If an attacker somehow obtains a valid device compliance ticket or uses AADInternals to flip a device record to 'Compliant,' it might only be caught if you cross-check with Intune's actual device inventory."></node>
          <node TEXT="One detection idea is if a device ID shows up in sign-in logs as compliant but Intune has no record of that device or reports it non-compliant - that discrepancy is a signal (requires joining data from Intune and Entra logs)."></node>
          <node TEXT="Gap: Without Intune data integration, Entra can be fooled - it doesn't inherently know the device state beyond what is reported to it."></node>
        </node>
      </node>
      <node TEXT="Fake Device Join">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="AADInternals can create device objects (there's a function to register devices via Graph)."></node>
          <node TEXT="Azure AD Graph API POST /devices could be used by an attacker with the right directory permissions."></node>
          <node TEXT="If the attacker compromises a user with the 'Device Enrollment Manager' role (for Intune) or uses a user account that hasn't hit its device limit, they can script device registrations."></node>
          <node TEXT="Another approach: steal the device certificate from a real device and reuse it on another machine - that effectively clones a join."></node>
          <node TEXT="Tools to extract device certificate and private key from a managed device (if not TPM-protected) could facilitate that."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="As mentioned, limit device joins (maybe only allow certain users or use Windows Autopilot with pre-registration to tightly control device entries)."></node>
          <node TEXT="If possible, implement verification for new devices - e.g., Conditional Access can require a device to be marked as compliant or hybrid joined; a fake Entra join alone may not suffice if the attacker can't also fake compliance or AD join."></node>
          <node TEXT="Regular cleanup: disable or delete devices that haven't logged sign-ins in a long time - this reduces chance an attacker can 'park' a fake device for later use."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Device enrollment restrictions in Entra/Intune can limit who can register/join devices and how many."></node>
          <node TEXT="Also, enabling Admin-approved device onboarding (preview) would require an admin to approve new device joins in some scenarios (not widely used, but conceptually an approach)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Entra Audit logs will show a device registration event (JoinType, etc.)."></node>
          <node TEXT="If an attacker registers a 'device' via API without actually having a real device, it still generates an audit entry."></node>
          <node TEXT="Comparing that with Intune enrollment logs might show no corresponding enrollment, which is odd if the device claims compliance."></node>
          <node TEXT="Also, one might catch this if multiple 'devices' are created by the same user in a short time through scripts."></node>
          <node TEXT="Gap: A successfully registered fake device is just an object in Entra - by itself, not harmful until used. It could sit unnoticed, especially if naming or identifiers don't stand out."></node>
        </node>
      </node>
    </node>
    <node TEXT="Multi-stage Attack Chaining">
      <node TEXT="Attack Path Mapping">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT=" BloodHound for on-prem AD and AzureHound (part of BloodHound tools) for Azure. BloodHound collects AD info via LDAP/SAMR (there's also SharpHound for AD data)"></node>
          <node TEXT="ROADtools can dump Entra configuration similarly."></node>
          <node TEXT="Stormspotter (an MS open-source project) maps out Azure resource relationships by querying Azure Resource Manager APIs."></node>
          <node TEXT="Attackers will use these or similar scripts to build a graph of relationships (users -> groups -> roles -> resources). Even basic PowerShell like Get-AzureADUserMembership and Get-AzRoleAssignment can enumerate a lot. These 'tools' are often run early to middle stage to figure out how to move laterally or escalate."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Eliminate easy paths - implement tiering so credentials at one level can't directly access higher-value systems."></node>
          <node TEXT="For example, even if an attacker maps out that a helpdesk account has privileged access on a workstation that a Domain Admin logs into, if you've separated admin workstations (PAW) and implemented tiered admins, that path is removed."></node>
          <node TEXT="In Azure, use resource segmentation: put critical resources in separate subscriptions or management groups with strict access, so an attacker mapping permissions finds dead-ends (they might see an owner on a dev subscription, but that doesn't help access prod)."></node>
          <node TEXT="Regularly run your own attack path discovery (with tools like BloodHound + AzureHound in a lab scenario) to understand and mitigate paths before attackers do."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Consider BloodHound Enterprise (a commercial tool) or Purple Knight (for AD) to proactively identify and close attack paths in AD."></node>
          <node TEXT="Entra's built-in recommendations (Identity Secure Score) can highlight risky configurations too."></node>
          <node TEXT="These aren't directly detecting attackers, but reducing the paths available."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="On-prem, Defender for Identity raises recon alerts (like LDAP enumeration, SAMR queries) which often precede attack path discovery."></node>
          <node TEXT="In Azure, there's less visibility - however, if an attacker uses tools like AzureHound (which call a lot of MS Graph and Azure RM APIs), you might observe a high volume of read queries from a single user or app."></node>
          <node TEXT="Custom Sentinel queries could catch a single principal enumerating hundreds of Azure objects (users, groups, roles) in a short period."></node>
          <node TEXT="Also, any suspicious use of directory read permission by a non-admin account could indicate mapping."></node>
        </node>
      </node>
      <node TEXT="Orchestration Frameworks">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Cobalt Strike is the most infamous (commercial red-team tool, often pirated by attackers)."></node>
          <node TEXT="Mythic C2 is an open-source framework that's modular and can emulate many techniques."></node>
          <node TEXT="Others include Empire, Covenant, PoshC2, Meterpreter (Metasploit)."></node>
          <node TEXT="hese frameworks allow attackers to script and automate multi-stage attacks (from recon, credential dumping, lateral movement, to persistence) and often leverage LOLBAS (Living-Off-the-Land Binaries and Scripts) - e.g., using rundll32, Regsvr32, or WMI for executing payloads to avoid detection."></node>
          <node TEXT="Attackers might use a less common framework to evade known signatures, but at the end of the day, they perform similar actions on hosts which defenders can detect if vigilant."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Network segmentation - ensure that even if a C2 agent runs on one host, it can't freely scan or move to others without crossing monitored boundaries."></node>
          <node TEXT="Credential hygiene - don't embed credentials in scripts or memory (C2 often scrapes creds to move; without creds, it's stuck)."></node>
          <node TEXT="Use LSA Protection/Credential Guard so the C2 can't easily harvest credentials to escalate."></node>
          <node TEXT="Regularly update AV/EDR signatures for latest C2 patterns."></node>
          <node TEXT="Employ honeytokens/honeyports - e.g., open a fake high-value port on a server and alert if anything tries to use it (some C2 frameworks might scan internally)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="AppLocker or Windows Defender Application Control to restrict execution of unauthorized binaries and scripts can seriously hinder C2 deployment. If the C2 can't run, it can't orchestrate."></node>
          <node TEXT="Network controls: restrict outbound internet access from servers so C2 can't call out easily (and use a proxy with logging for outbound traffic)."></node>
          <node TEXT="Many EDRs have attack surface reduction rules that can block behaviours often used by C2 loaders (like blocking Office from spawning script interpreters)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Endpoint Detection and Response (EDR) is critical here - C2 frameworks have distinct behaviours (e.g., Cobalt Strike beacons, which many EDRs detect via memory signatures or traffic patterns)."></node>
          <node TEXT="Network IDS/IPS can also pick up known C2 traffic (some beacon traffic, default malleable profiles, etc.)."></node>
          <node TEXT="If an attacker uses a custom or less common framework (Mythic, Covenant, etc.), detection relies on behaviour: e.g., a process spawning that typically doesn't (like dllhost.exe making network connections, or MSBuild.exe running payloads)."></node>
          <node TEXT="Correlating unusual child processes (like Word spawning a weird child process) is also telling of C2 stage."></node>
        </node>
      </node>
    </node>
    <node TEXT="Reconnaissance">
      <node TEXT="Unauthenticated">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="Attackers use very simple methods: browse to Azure login, enter guessed usernames to see if the error is 'password incorrect' vs 'no such user' (that reveals valid accounts)."></node>
          <node TEXT="They will also query DNS for MX records (to see if you use O365 - thus Entra)."></node>
          <node TEXT="Microsoft Graph unauthenticated endpoints, such as checking the domain in the /common endpoint responses to infer tenant ID."></node>
          <node TEXT="OpenID configuration URLs (for example, https://login.microsoftonline.com/{tenantid}/.well-known/openid-configuration) yields tenant info."></node>
          <node TEXT="AADInternals"></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Privacy - minimize public exposure of identity information. For instance, do not enable federation metadata that exposes too much info publicly."></node>
          <node TEXT="Ensure employee lists aren't public, to limit attacker ease of user enumeration."></node>
          <node TEXT="For Entra specifically, you can't hide the basic tenant discovery (if an attacker knows your domain, Entra will reveal if it's a valid tenant during login)."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Not much on Microsoft's side for purely unauthenticated recon."></node>
          <node TEXT="Threat intelligence services can alert if your company is mentioned on dark web or if typosquatting domains appear."></node>
          <node TEXT="Some companies deploy canary tokens (like unique fake email addresses) to see if they get targeted - not a Microsoft tool, but a strategy."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="Many recon activities externally don't hit your logs (e.g., scanning login pages, enumerating via web APIs)."></node>
          <node TEXT="However, some may - e.g., an attacker using the OIDC /.well-known/openid-configuration URL for your tenant or trying to find tenant ID via login responses. Those aren't logged in Entra sign-ins."></node>
          <node TEXT="One detection method is external: monitor for your domain being targeted on paste sites or in attacker chatter."></node>
          <node TEXT="Also, if you set up dummy accounts (honeypot emails) and they receive phishing or password reset emails, that can indicate enumeration."></node>
          <node TEXT="Gap: Largely, unauthenticated recon is out of your view. You rely on threat intelligence or the attacker tripping an early alarm by using a known bad IP that gets flagged by Microsoft (though that would be very indirect)."></node>
        </node>
      </node>
      <node TEXT="Authenticated">
        <node TEXT="Offensive Tools and LOLBAS">
          <node TEXT="If an attacker logs in as a regular user, they can use AADInternals to dump tenant info (it can run many Graph queries with a user token)."></node>
          <node TEXT="ROADtools can similarly pull information with user-level access (some data like other users' details, groups, application listings that are not privileged)."></node>
          <node TEXT="GraphRunner"></node>
          <node TEXT="GraphPython"></node>
          <node TEXT="Microsoft Graph - e.g. Microsoft Graph PowerShell module - a low-privilege user can still call Get-MgUser -All and retrieve a list of users (unless tenant restrictions are in place)."></node>
          <node TEXT="Azure AD Graph"></node>
          <node TEXT="For on-prem AD, the classic AD PowerShell or ldapsearch via VPN could be used by a compromised user to read AD (since Authenticated Users have broad read)."></node>
          <node TEXT="Attackers will also use Outlook/Exchange - if they have mailbox access, they might search Global Address List or emails for sensitive info as part of recon."></node>
        </node>
        <node TEXT="Preventative Controls (Hardening)">
          <node TEXT="Limit default permissions - by design, every user can read some directory info (like other users' names, group memberships, etc.) in Entra. You can restrict this by setting the User object property 'DirectoryReaders' role removal (Microsoft provides a method to create a security group and deny its members the ability to read other users - effectively a privacy mode)."></node>
          <node TEXT="On AD on-prem, use 'Authenticated Users' read permission lockdowns for sensitive objects (though usually not practical to remove default reads)."></node>
          <node TEXT="Keep critical group membership (like admins) confidential if possible."></node>
        </node>
        <node TEXT="Preventative Tools">
          <node TEXT="Entra has a setting 'User access to Entra admin portal' - you can turn this off for non-admins so they can't browse directory info in the portal."></node>
          <node TEXT="That prevents a compromised normal user from easily listing all users or groups in the GUI."></node>
          <node TEXT="Also consider role-based access: don't give regular users directory read roles."></node>
          <node TEXT="Logging and alerting - set up Sentinel queries for if a normally non-admin user attempts to enumerate Azure resources (for example, lots of 'List directory roles' operations via Graph - though getting that detail may require MCAS or Graph audit)."></node>
        </node>
        <node TEXT="Detection Sources">
          <node TEXT="If an attacker has obtained a standard user credential and is enumerating internally, Defender for Identity on-prem can catch AD queries (like an unusual user reading lots of AD objects)."></node>
          <node TEXT="In Entra, look at sign-in logs for that user: are they calling Microsoft Graph API extensively (which might show up as multiple 'Interactive sign-in' entries if using Graph Explorer or as 'Non-interactive' token issues for Graph)?"></node>
          <node TEXT="Entra doesn't log the specific API calls, but you might see usage of certain applications (e.g., Graph API, Exchange Online PowerShell) by an account that normally wouldn't."></node>
          <node TEXT="Also, any unusual Azure Portal or PowerShell usage by a user (visible via audit logs: 'User accessed Entra blade' etc.) could indicate recon."></node>
          <node TEXT="If you can, enable ingestiong of the Microsoft Graph Activity logs."></node>
        </node>
      </node>
    </node>
  </node>
</map>