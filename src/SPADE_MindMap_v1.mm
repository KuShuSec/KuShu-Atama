<map version="0.9.0">
  <node TEXT="Side-channel Platform Abuse &amp; Data Exfiltration (SPADE)&#10;Cloud Abuse Model&#10;https://github.com/KuShuSec">
    <node TEXT="Core Concepts">
      <node TEXT="SPADE: Side-channel Platform&#10;Abuse &amp; Data Exfiltration"></node>
      <node TEXT="ALIEN: Abuse of Legitimate&#10;Integration ENgines"></node>
      <node TEXT="Trust abuse, not&#10;vulnerability exploitation"></node>
    </node>
    <node TEXT="Abuse Vectors">
      <node TEXT="SaaS Notebooks">
        <node TEXT="Google Colab&#10;(non-Enterprise)"></node>
        <node TEXT="Kaggle Kernels"></node>
        <node TEXT="SageMaker Studio Lab"></node>
        <node TEXT="Databricks&#10;Community&#10;Edition"></node>
      </node>
      <node TEXT="Low/No-Code Platforms">
        <node TEXT="Zapier / Make.com"></node>
        <node TEXT="Power Automate&#10;(unmanaged)"></node>
        <node TEXT="Retool / IFTTT / n8n"></node>
      </node>
      <node TEXT="Online IDEs &amp; Labs">
        <node TEXT="Replit / Gitpod /&#10;StackBlitz"></node>
        <node TEXT="labs.iximiuz.com"></node>
        <node TEXT="CodeSandbox / Glitch"></node>
      </node>
      <node TEXT="Streaming&#10;Desktops /&#10;Containers">
        <node TEXT="Kasm Workspaces"></node>
        <node TEXT="Amazon&#10;Workspaces&#10;Web"></node>
        <node TEXT="Shells / Nutanix Frame"></node>
      </node>
      <node TEXT="Online Sandboxes">
        <node TEXT="Any.Run"></node>
        <node TEXT="Joe Sandbox /&#10;Hybrid Analysis"></node>
        <node TEXT="Triage / Cape Sandbox"></node>
      </node>
    </node>
    <node TEXT="Techniques">
      <node TEXT="Runtime Code Execution"></node>
      <node TEXT="Outbound API Exfiltration"></node>
      <node TEXT="OAuth Token Abuse"></node>
      <node TEXT="Bypassing DLP /&#10;Proxy / EDR"></node>
    </node>
    <node TEXT="Indicators of Abuse">
      <node TEXT="Unknown API Calls&#10;from SaaS IPs"></node>
      <node TEXT="GitHub commits via&#10;API, not browser"></node>
      <node TEXT="Colab activity&#10;without Drive/Docs"></node>
      <node TEXT="Clipboard or notebook&#10;paste injection"></node>
    </node>
    <node TEXT="Controls &amp; Mitigations">
      <node TEXT="Harden SaaS&#10;OAuth Scopes"></node>
      <node TEXT="Disable Free-tier&#10;Compute Access"></node>
      <node TEXT="Restrict to Enterprise Versions &#10;with strong tenanted controls "></node>
      <node TEXT="Enforce Non-Persistent locked down&#10; VDI for Cloud IDEs/Sandboxes"></node>
      <node TEXT="DLP + API&#10;Inspection on&#10;Egress"></node>
      <node TEXT="Region Lock&#10;Execution&#10;Environments"></node>
      <node TEXT="CASB">
        <node TEXT="Cannot prevent&#10;remote execution"></node>
        <node TEXT="Can block clipboard/paste and file&#10;upload into SaaS IDEs"></node>
        <node TEXT="Effective with scoped&#10;controls and app detection"></node>
      </node>
    </node>
    <node TEXT="LOTS &#x2013; Living Off&#10;Trusted Services">
      <node TEXT="Use of trusted services/APIs to&#10;evade traditional detection"></node>
      <node TEXT="Trusted API Targets">
        <node TEXT="GitHub"></node>
        <node TEXT="Google Cloud Storage"></node>
        <node TEXT="Pastebin / Mastodon /&#10;Discord Webhooks"></node>
        <node TEXT="Microsoft Graph /&#10;Entra / OneDrive"></node>
      </node>
      <node TEXT="Examples">
        <node TEXT="Colab committing to&#10;GitHub via API"></node>
        <node TEXT="Zapier POSTing&#10;to a webhook"></node>
        <node TEXT="Replit accessing&#10;storage.googleapis.com"></node>
        <node TEXT="make.com for&#10;webhook exfil or API access"></node>
      </node>
      <node TEXT="Data Sovereignty Bypass">
        <node TEXT="Colab executes in regions that may contravene &#10;organisational policy"></node>
      </node>
      <node TEXT="SOC Blind Spots">
        <node TEXT="No endpoint log"></node>
        <node TEXT="API egress&#10;looks legitimate"></node>
        <node TEXT="DLP/CASB&#10;allowlisted&#10;domains"></node>
      </node>
    </node>
  </node>
</map>