<map version="0.9.0">
  <node TEXT="M365 Breakglass Immaturity Model&#10;&#10;GitHub.com/KuShuSec v1">
    <node TEXT="&#x1F525; Fire Hazard">
      <node TEXT="Used for daily operations"></node>
      <node TEXT="No MFA enforced"></node>
      <node TEXT="Password never rotated"></node>
      <node TEXT="Account exempt from logging"></node>
      <node TEXT="Alerts suppressed or ignored"></node>
      <node TEXT="Used from unmanaged or insecure devices"></node>
      <node TEXT="Password reused anywhere else in the tenant or on-prem AD"></node>
      <node TEXT="Sign-ins allowed from any country and any IP range instead of a privileged access workstation (PAW)"></node>
      <node TEXT="Global Administrator kept eligible in PIM rather than permanent (breakglass must bypass PIM)"></node>
      <node TEXT="Only one breakglass account exists, so any lockout of that identity is catastrophic"></node>
    </node>
    <node TEXT="&#x1F511; Shared Secrets">
      <node TEXT="Account shared between multiple people"></node>
      <node TEXT="Password stored in plaintext or password manager"></node>
      <node TEXT="No usage audit trail"></node>
      <node TEXT="Used for routine mailbox or SharePoint tasks"></node>
      <node TEXT="No individual accountability or auditability"></node>
      <node TEXT="Used for Logic Apps, Power Automate, or integration auth"></node>
      <node TEXT="Credential copies emailed, pasted in chat, or sitting in ticket history"></node>
      <node TEXT="Stored in DevOps variable groups that a broad set of engineers can read"></node>
      <node TEXT="Injected by automation into containers or function apps without secret-rotation workflow"></node>
      <node TEXT="No quarterly attestation forcing each individual to re-confirm &quot;I still know this secret&quot;"></node>
      <node TEXT="Account federated to on-prem IdP, so if ADFS is down the secret is useless"></node>
    </node>
    <node TEXT="&#x1F573;&#xFE0F; Hidden Traps">
      <node TEXT="Credentials embedded in scripts or pipelines"></node>
      <node TEXT="Breakglass excluded from Conditional Access as workaround"></node>
      <node TEXT="Cloud-only account with no backup recovery route"></node>
      <node TEXT="Licensed for all services, increasing attack surface"></node>
      <node TEXT="Risk-based policies include the account, meaning a high-risk sign-in might be blocked during an actual crisis"></node>
      <node TEXT="Alternate email and phone set to an ex-employee who is now unreachable"></node>
      <node TEXT="Account subject to automated cleanup because it has not signed in within the last X days"></node>
    </node>
    <node TEXT="&#x1F648; We Don&#x2019;t Talk About Breakglass">
      <node TEXT="No documentation or ownership"></node>
      <node TEXT="Never tested"></node>
      <node TEXT="No out-of-band recovery plan"></node>
      <node TEXT="Relying on 'we&#x2019;ll just reset it'"></node>
    </node>
    <node TEXT="&#x1F4C9; Governance">
      <node TEXT="Runbook rests in a SharePoint site that itself requires normal SSO to open"></node>
      <node TEXT="No dual-administrator approval recorded when the password envelope is opened"></node>
      <node TEXT="Recovery exercise never scheduled after tenant migrations or CA revisions"></node>
      <node TEXT="Owner left the company; their replacement was never assigned in Entra ID"></node>
      <node TEXT="Incident-response team unaware of the existence of the account until an outage happens"></node>
      <node TEXT="Post-use review does not revoke the password, leaving an unknown number of copies in circulation"></node>
    </node>
  </node>
</map>