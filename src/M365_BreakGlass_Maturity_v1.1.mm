<map version="0.9.0">
  <node TEXT="M365 BreakGlass Maturity Model&#10;&#10;GitHub.com/KuShuSec v1.1">
    <node TEXT="Unprepared">
      <node TEXT="No breakglass account or app."></node>
      <node TEXT="No documented recovery process."></node>
      <node TEXT="Breakglass = &#x201C;hope it never happens.&#x201D;"></node>
    </node>
    <node TEXT="Reactive">
      <node TEXT="Breakglass account exists but rarely tested."></node>
      <node TEXT="App registrations are&#10;unmanaged and unmonitored."></node>
      <node TEXT="Secrets stored in plain text or&#10;left to expire unnoticed."></node>
      <node TEXT="Application Admin is assigned&#10;permanently to a few users."></node>
      <node TEXT="Offline credentials (e.g., passphrase or&#10;QR) stored in secure location."></node>
    </node>
    <node TEXT="Baseline Hygiene">
      <node TEXT="App secrets tracked manually; redirect&#10;URIs reviewed occasionally."></node>
      <node TEXT="Some use of PIM for&#10;privileged roles."></node>
      <node TEXT="App Admin role assignments&#10;starting to be reduced."></node>
      <node TEXT="Breakglass CA exclusions are tightly scoped &#x2014; only&#10;exclude policies that may block emergency recovery&#10;(e.g. device state), but maintain sign-in risk or location&#10;checks where feasible."></node>
    </node>
    <node TEXT="Controlled">
      <node TEXT="Application Admin role only&#10;PIM-eligible with approval workflows."></node>
      <node TEXT="Privileged role assignments&#10;reviewed via Access Reviews."></node>
      <node TEXT="Consent grants require&#10;admin approval."></node>
      <node TEXT="Breakglass account uses&#10;FIDO2/passkey backed MFA."></node>
      <node TEXT="Secrets have defined expiry; basic&#10;automation for renewal exists."></node>
      <node TEXT="Redirect URIs are&#10;strictly scoped."></node>
      <node TEXT="Monitoring for service&#10;principal logins is in place."></node>
    </node>
    <node TEXT="Secure by Design">
      <node TEXT="All workload identities use Workload&#10;Identity Federation (WIF)."></node>
      <node TEXT="Secrets/certs fully automated via key&#10;vault or secure pipelines."></node>
      <node TEXT="Workload identity Conditional&#10;Access policies enforced."></node>
      <node TEXT="Entra Workload ID Premium&#10;licensing applied universally."></node>
      <node TEXT="Alerts for anomalous app behavior&#10;integrated into SIEM/SOAR."></node>
      <node TEXT="Recovery procedures are&#10;documented, tested quarterly."></node>
      <node TEXT="Breakglass application&#10;exists with clear scoping."></node>
      <node TEXT="Adversary emulation (e.g., purple team)&#10;used to validate response."></node>
      <node TEXT="Recovery planning accounts for&#10;Microsoft service outages,&#10;misconfigurations, and attacker&#10;scenarios."></node>
    </node>
    <node TEXT="Automated &amp; Resilient">
      <node TEXT="Entire breakglass app process is&#10;policy-as-code, version-controlled."></node>
      <node TEXT="All privileged app access paths are&#10;just-in-time and require approval."></node>
      <node TEXT="RBAC, CA, identity protection, and&#10;detection rules applied to workload&#10;identities just like user identities."></node>
      <node TEXT="Continuous posture monitoring&#10;via Defender for Cloud or Entra&#10;Identity Governance."></node>
      <node TEXT="Disaster recovery simulation of&#10;breakglass scenario part of regular&#10;purple team exercises."></node>
    </node>
    <node TEXT="Isolated Resilience">
      <node TEXT="Breakglass identity/app hosted&#10;in external (red) tenant."></node>
      <node TEXT="Red tenant identity has&#10;just-in-time access into primary&#10;tenant via B2B or B2B Direct."></node>
      <node TEXT="Red tenant identity protected with&#10;independent security stack."></node>
      <node TEXT="Offline access credential backup exists&#10;(QR code, physical token, etc)."></node>
      <node TEXT="Breakglass identity or app optionally backed by&#10;alternate identity provider or tenant to avoid&#10;dependency on primary cloud platform."></node>
    </node>
  </node>
</map>