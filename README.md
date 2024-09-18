# Awesome AD (Active Directory) [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of awesome Microsoft Active Directory Domain Services, Certificate Services, Federation Services, and other related references.

## Contents

- [Blogs](#blogs)
- [Certificate Services](#adcs)
- [Domain Services](#adds)
- [Entra](#entra)
- [Fundamentals](#fundamentals)
- [PowerShell](#ps)
- [Privileged Access Workstations](#paw)
- [Windows Server](#ws)

## Blogs

- [AJ's Tech Chatter](https://anthonyfontanez.com/)
- [Alan Burchill](https://www.grouppolicy.biz/)
- [Carsten Sandker](https://csandker.io/)
- [Cas van Cooten](https://casvancooten.com/posts/)
- [Chris Brown](https://chrisbrown.au/techblog/)
- [Chris Brumm](https://chris-brumm.com/)
- [Christoffer Andersson](https://blog.chrisse.se/)
- [Core Infra & Sec Blog](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/bg-p/CoreInfrastructureandSecurityBlog) 
- [Daniel Chronlund](https://danielchronlund.com/)
- [Eric Woodruff](https://ericonidentity.com/)
- [Fabian Bader](https://cloudbrothers.info/)
- [Jake Hildreth](https://trimarcjake.github.io/blog/)
- [Jay Paloma](https://jpaloma.wordpress.com/)
- [Jeffrey Appel](https://jeffreyappel.nl/)
- [Merill Fernando](https://merill.net/)
- [Michael Soule](https://snozzberries.github.io/)
- [Narayanan Subramanian](https://medium.com/@nannnu) 
- [Nathan McNulty](https://blog.nathanmcnulty.com/)
- [Przemysław Kłys](https://evotec.xyz/hub/)
- [Ravenswood](https://www.ravenswoodtechnology.com/blog/)
- [Robin Granberg](https://managedpriv.com/blog/)
- [Ru Campbell](https://campbell.scot/)
- [Ryan Ries](https://ryanries.github.io/)
- [Sam Erde](https://day3bits.com/)
- [Sean Metcalf](https://adsecurity.org/)
- [Steve Syfuhs](https://syfuhs.net/)
- [Trimarc](https://www.hub.trimarcsecurity.com/posts) 
- [zer1t0](https://zer1t0.gitlab.io/posts/)

## ADCS

> Active Directory Certificate Services

- [Cert Template Storage](https://learn.microsoft.com/en-us/archive/technet-wiki/8464.certificate-templates-and-their-storage-within-active-directory)
- [Cert Web Enrollment](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/we-need-to-discuss-the-microsoft-certification-authority-web/ba-p/4070976)
- [CS Security](https://learn.microsoft.com/en-us/archive/technet-wiki/10942.ad-cs-security-guidance)
- [Design Guide](https://learn.microsoft.com/en-us/archive/technet-wiki/7421.active-directory-certificate-services-ad-cs-public-key-infrastructure-pki-design-guide)
- [Ent CA](https://learn.microsoft.com/en-us/archive/technet-wiki/53249.active-directory-certificate-services-enterprise-ca-architecture)
- [Lab Guide](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831348)
- [Locksmith](https://github.com/TrimarcJake/Locksmith)
- [NDES](https://learn.microsoft.com/en-us/archive/technet-wiki/9063.active-directory-certificate-services-ad-cs-network-device-enrollment-service-ndes)
- [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)
- [Site Awareness](https://learn.microsoft.com/en-us/archive/technet-wiki/14106.ad-ds-site-awareness-for-ad-cs-and-pki-clients)

## ADDS

> Active Directory Domain Services

- [ACL Visualizer](https://github.com/lkarlslund/Adalanche)
- [ACSC Log Forwarding](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)
- [Active Directory Best practices](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc778219)
- [Active Directory Health Check: Troubleshooting](https://learn.microsoft.com/en-us/archive/technet-wiki/32911.active-directory-health-check-troubleshooting)
- [AD Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
- [AD Checklist](https://github.com/mczerniawski/Active-Directory-CheckList/tree/master)
- [AD Discovery Checklist](https://learn.microsoft.com/en-us/archive/technet-wiki/38512.active-directory-domain-discovery-checklist)
- [AD Technical Reference Collection](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc780036)
- [AD Ultimate Reading Collection](https://learn.microsoft.com/en-us/archive/technet-wiki/20964.active-directory-ultimate-reading-collection)
- [ADACLScanner](https://github.com/canix1/ADACLScanner)
- [AD-permissions](https://github.com/ANSSI-FR/AD-permissions)
- [ADRecon](https://github.com/adrecon/ADRecon)
- [ADSec PowerShell](https://github.com/PSSecTools/ADSec)
- [Ask DS Archive](https://learn.microsoft.com/en-us/archive/blogs/askds/)
- [Authentication Policies](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos)
- [Azure Secure Isolation](https://learn.microsoft.com/en-us/azure/azure-government/azure-secure-isolation-guidance)
- [Azure Sentinel Insecure Protocols Workbook Implementation Guide](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/azure-sentinel-insecure-protocols-workbook-implementation-guide/ba-p/1197564)
- [Best Practice Active Directory Design for Managing Windows Networks](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727085)
- [Best practices for assigning permissions on Active Directory objects](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786285)
- [Best Practices for Securing AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Bloodhound](https://github.com/SpecterOps/BloodHound)
- [BlueTuxedo](https://github.com/TrimarcJake/BlueTuxedo)
- [CISA Logging Made Easy](https://github.com/cisagov/LME)
- [Diagnostic Logging](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961809)
- [Disabling NTLMv1](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/active-directory-hardening-series-part-1-disabling-ntlmv1/ba-p/3934787)
- [EventLogging](https://github.com/blackhillsinfosec/EventLogging)
- [GPOZaurr](https://github.com/EvotecIT/GPOZaurr)
- [Legacy DOE AD Design](https://web.archive.org/web/20120418025316/http://www.doecirc.energy.gov/documents/MS_Active_Directory_Design_Guide.pdf)
- [Location Mapping](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727034)
- [MCM AD Internals](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/mcm-core-active-directory-internals/ba-p/1785782)
- [Microsoft AD DS Tuning](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/)
- [Microsoft Blue Forest](https://github.com/rootsecdev/Microsoft-Blue-Forest/tree/master)
- [MIM PAM](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)
- [Monash EAM](https://github.com/mon-csirt/active-directory-security/tree/main)
- [Palantir Windows Event Forwarding](https://github.com/palantir/windows-event-forwarding)
- [Pingcastle](https://github.com/netwrix/pingcastle)
- [Protecting Tier 0 the Modern Way](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/protecting-tier-0-the-modern-way/ba-p/4052851)
- [Scheduled Task PowerShell](https://stackoverflow.com/questions/42801733/creating-a-scheduled-task-which-uses-a-specific-event-log-entry-as-a-trigger)
- [ScriptSentry](https://github.com/techspence/ScriptSentry)
- [SelfADSI](http://www.selfadsi.org/index.htm)
- [SS64 Groups](https://ss64.com/nt/syntax-groups.html)
- [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [System Security Services Daemon](https://docs.pagure.org/sssd.sssd/index.html)
- [T0 User Management Scripts](https://github.com/Kili69/Tier0-User-Management)
- [T0 Windows Admin Center](https://www.ravenswoodtechnology.com/how-to-build-a-tier-0-windows-admin-center-instance/)
- [Untrusted Regions](https://www.youtube.com/watch?v=Tf40Y-qrUYE)
- [Visual Auditing](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel)
- [Windows Event Forwarding](https://github.com/PSSecTools/WindowsEventForwarding)

## Entra

- [AADAppAudit](https://github.com/jsa2/AADAppAudit/tree/main)
- [Awesome Entra](https://github.com/merill/awesome-entra)
- [Azure Attack Paths](https://cloudbrothers.info/azure-attack-paths/)
- [Azure Red Team](https://github.com/rootsecdev/Azure-Red-Team)
- [CAOptics](https://github.com/jsa2/caOptics)
- [Conditional Access Automation](https://www.cloud-architekt.net/conditional-access-automation/)
- [Entra Assessment](https://github.com/AzureAD/AzureADAssessment)
- [Entra Attack & Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense?WT.mc_id=m365-0000-rotrent)
- [Entra Exporter](https://github.com/microsoft/entraexporter)
- [Entra ID Governance Training](https://github.com/microsoft/EntraIDGovernance-Training)
- [Entra Kill Chain](https://aadinternals.com/aadkillchain/)
- [Entra Tiering](https://github.com/weskroesbergen/Entra-Tiering-Security-Model)
- [EntraOps](https://github.com/Cloud-Architekt/EntraOps)
- [M365DSC](https://github.com/microsoft/Microsoft365DSC)
- [Maester](https://github.com/maester365/maester)
- [Managed Identity Attack Paths](https://posts.specterops.io/managed-identity-attack-paths-part-3-function-apps-300065251cbe)
- [Modern Authentication Attacks](https://jeffreyappel.nl/tips-for-preventing-against-new-modern-identity-attacks-aitm-mfa-fatigue-prt-oauth/)
- [Restricted Management Admin Units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management)
- [Rogue Office 365 and Azure (active) Directory (ROAD) tools](https://github.com/dirkjanm/ROADtools)
- [Unified Audit Log Policy](https://github.com/nathanmcnulty/nathanmcnulty/blob/master/ExchangeOnline/New-UALRetentionPolicy.ps1)

## Fundamentals

- [Azure Security Fundamentals](https://learn.microsoft.com/en-us/azure/security/fundamentals/)
- [Emergency Access](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Google On Fire Drills and Phishing Tests](https://security.googleblog.com/2024/05/on-fire-drills-and-phishing-tests.html)
- [M365 ZT Mindmaps](https://github.com/JadKaraki/M365ZeroTrust/)
- [Microsoft App Assure](https://www.microsoft.com/en-us/fasttrack/microsoft-365/app-assure)
- [Microsoft Gov Compliance](https://aka.ms/MSGovCompliance)
- [Microsoft Open Specs](https://learn.microsoft.com/en-us/openspecs/main/ms-openspeclp/3589baea-5b22-48f2-9d43-f5bea4960ddb)
- [Microsoft SecCon Framework Legacy](https://github.com/microsoft/SecCon-Framework)
- [Microsoft Security Academy](https://microsoft.github.io/PartnerResources/skilling/microsoft-security-academy)
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Post-Grad AD Studies](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/post-graduate-ad-studies/ba-p/398057?source=post_page-----b665399d252f--------------------------------)
- [Scream Test Unused Servers](https://www.microsoft.com/insidetrack/blog/microsoft-uses-a-scream-test-to-silence-its-unused-servers/)
- [Unclassified DISA STIGs](https://www.stigviewer.com/stigs)
- [Zero-Trust RAMP Landing Page](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-ramp-overview)

## PS

> PowerShell

- [PowerShell Constrained Language Mode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes)
- [PowerShell JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)
- [PowerShell JEA Legacy](https://github.com/PowerShell/JEA)

## PAW

> Privileged Access Workstations

- [Defender Application Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/)
- [Entra Joined Firewall](https://anthonyfontanez.com/index.php/2021/09/16/windows-firewall-part-6-azure-ad-joined-clients/)
- [ETSI PAW Spec](https://www.etsi.org/deliver/etsi_ts/103900_103999/10399401/01.01.01_60/ts_10399401v010101p.pdf)
- [Evergreen](https://github.com/aaronparker/evergreen)
- [Hardening Kitty](https://github.com/scipag/HardeningKitty)
- [Intune Maps](https://intunemaps.com/)
- [IntuneCD](https://github.com/almenscorner/IntuneCD)
- [Local Sec Group Monitoring](https://www.verboon.info/2024/02/monitoring-windows-built-in-local-security-groups-with-microsoft-defender-xdr-or-sentinel/)
- [MDE Tester](https://github.com/LearningKijo/MDEtester)
- [Microsoft Cloud PAW Scripts Legacy](https://github.com/microsoft/Cloud-PAW-Management)
- [Microsoft Secured Workstation](https://github.com/Azure/securedworkstation/tree/master)
- [NCSC Windows Device Security Guidance](https://www.ncsc.gov.uk/collection/device-security-guidance/platform-guides/windows)
- [Open Intune Baseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline)
- [OSDCloud](https://www.osdcloud.com/)
- [PackageFactory](https://github.com/aaronparker/packagefactory)
- [PAW Deploy](https://github.com/DeploymentBunny/PAWDeploy)
- [PAW HGS](https://learn.microsoft.com/en-us/archive/blogs/datacentersecurity/privileged-access-workstationpaw)
- [PAW Scripts](https://github.com/utsecnet/PAW)
- [Privileged Access Landing Page](https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview)
- [Windows Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

## WS

> Windows Server

- [Secured-core Server](https://learn.microsoft.com/en-us/windows-server/security/secured-core-server)
- [Shielded VMs](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node)
