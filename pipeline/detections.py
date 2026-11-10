# Oportunidades de detecção por grupo prioritário. Regras Sigma comportamentais (não IOCs efêmeros).
# Cada entrada: mitre id do grupo, resumo de TTP, telemetria, regras Sigma (YAML), justificativa, gaps/bypasses.
PRIORITY = [
 dict(mitre="G0007", title="APT28 / Sofacy / Fancy Bear / Forest Blizzard (RU-GRU 26165)",
  ttp="Spearphishing e password spraying contra Exchange/OWA e M365; exploração de roteadores e CVE-2023-23397 (Outlook NTLM leak); "
      "implants X-Agent/Zebrocy/HeadLace; abuso de serviços legítimos (Mocky, webhook.site) para staging.",
  telemetry=["Entra ID SignInLogs / AADNonInteractiveUserSignInLogs", "Exchange MessageTrace / Mailbox audit (MailItemsAccessed)",
             "Sysmon EID 1/3 ou Defender DeviceProcessEvents/DeviceNetworkEvents", "Logs de firewall/proxy (SMB 445 de saída)"],
  sigma=["""title: Outlook Initiating Outbound SMB/WebDAV to External Host (CVE-2023-23397 pattern)
id: 6a3f1c2e-8b1d-4f4a-9c55-7e2c0b9a1f01
status: experimental
description: Detects OUTLOOK.EXE connecting to external hosts over SMB (445) or WebDAV, consistent with NTLM hash leak abuse attributed to APT28.
references:
    - https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.credential-access
    - attack.t1187
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\\OUTLOOK.EXE'
        DestinationPort:
            - 445
            - 139
    filter_private:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '127.0.0.0/8'
    condition: selection and not filter_private
falsepositives:
    - Raras; mapeamentos legítimos de compartilhamentos externos via Outlook
level: high
""", """title: Password Spray Pattern - Many Accounts Failing From Single Source
id: 0c7d5a10-2b55-4b0e-8d7e-91f3a4e1b202
status: experimental
description: Detects a single IP failing authentication for many distinct users (spray), a recurrent APT28/APT33 initial-access technique against M365/OWA.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.credential-access
    - attack.t1110.003
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType:
            - 50126
            - 50053
    condition: selection
falsepositives:
    - Proxies/NAT corporativos; ajustar agregação por IP e janela
level: medium
"""],
  why="A regra de Outlook foca no comportamento estrutural (processo de cliente de e-mail iniciando SMB para internet) e não em IPs de C2, que rotacionam. "
      "A regra de spray deve ser agregada (count distinct UserPrincipalName por IPAddress em 1h > 20) no SIEM – a parte de agregação está nas consultas KQL/SPL abaixo.",
  extra_kql="""SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126","50053")
| summarize Users=dcount(UserPrincipalName), Apps=make_set(AppDisplayName) by IPAddress, bin(TimeGenerated, 1h)
| where Users > 20""",
  extra_spl="""index=azure sourcetype=azure:aad:signin (ResultType=50126 OR ResultType=50053)
| bin _time span=1h
| stats dc(UserPrincipalName) as users values(AppDisplayName) as apps by IPAddress _time
| where users > 20""",
  gaps="Sem Sysmon EID 3 ou MDE, a conexão do Outlook não é visível; tráfego via roteadores comprometidos (SOHO residencial) contorna listas de reputação; spray 'low and slow' abaixo do limiar."),

 dict(mitre="G0016", title="APT29 / Cozy Bear / Midnight Blizzard (RU-SVR)",
  ttp="Abuso de identidade em nuvem: password spray em contas legadas sem MFA, criação de OAuth apps e concessão de app roles (full_access_as_app), "
      "golden SAML/AD FS, supply chain (SolarWinds), WINELOADER/GraphicalProton via HTML smuggling.",
  telemetry=["Entra ID AuditLogs (Add service principal credentials, Consent to application, Add app role assignment)",
             "Unified Audit Log (MailItemsAccessed)", "AD FS Admin/Security logs (EID 1200/1202, 70)", "Defender for Cloud Apps"],
  sigma=["""title: Credentials Added To Service Principal Or Application
id: 4b1f9d3a-6f2e-4a18-a0b6-2d7c3e5f8a03
status: experimental
description: New secret/certificate added to an app registration or service principal, used by APT29 to persist via OAuth apps after initial compromise.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1098.001
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName:
            - 'Add service principal credentials'
            - 'Update application - Certificates and secrets management'
    condition: selection
falsepositives:
    - Rotação planejada de segredos por DevOps; correlacionar com change management
level: medium
""", """title: High-Privilege App Role Granted To Application (full_access_as_app / Mail.Read)
id: 9e2c4d71-0a3b-4c6d-8f19-5b7a2e1c9d04
status: experimental
description: Detects assignment of application permissions commonly abused for mailbox exfiltration (Midnight Blizzard 2024 intrusion).
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.privilege-escalation
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName: 'Add app role assignment to service principal'
        TargetResources|contains:
            - 'full_access_as_app'
            - 'Mail.Read'
            - 'Mail.ReadWrite'
            - 'RoleManagement.ReadWrite.Directory'
    condition: selection
falsepositives:
    - Onboarding de ferramentas de backup/e-discovery
level: high
"""],
  why="APT29 privilegia persistência baseada em identidade, invisível para EDR de endpoint. As regras monitoram mudanças de controle-plane (credenciais e permissões de aplicações), que são raras e de alto valor.",
  extra_kql="""AuditLogs
| where OperationName in ("Add service principal credentials","Add app role assignment to service principal","Consent to application")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, App, TargetResources""",
  extra_spl="""index=azure sourcetype=azure:aad:audit (operationName="Add service principal credentials" OR operationName="Add app role assignment to service principal" OR operationName="Consent to application")
| table _time operationName initiatedBy.user.userPrincipalName targetResources{}.displayName""",
  gaps="Licenciamento E5 necessário para MailItemsAccessed; uso de proxies residenciais; tokens roubados (pass-the-cookie) não geram falha de login; AD FS sem auditoria habilitada impede ver Golden SAML."),

 dict(mitre="G0034", title="Sandworm Team / Seashell Blizzard (RU-GRU 74455)",
  ttp="Destrutivo: wipers (NotPetya, Industroyer2, CaddyWiper, AcidRain), implantação via GPO, uso de PowerShell/Impacket e ataques a OT/ICS.",
  telemetry=["Security EID 5136/5137 (alterações de GPO)", "Sysmon EID 1/11/23 ou DeviceFileEvents", "SYSVOL file monitoring", "Telemetria OT (Zeek/ICS protocol parsers)"],
  sigma=["""title: Scheduled Task Or Executable Dropped Into SYSVOL Policies
id: 2f8a6c19-3d4e-4b5a-9c7d-1e0f2a3b4c05
status: experimental
description: Detects creation of scripts/executables/ScheduledTasks.xml under SYSVOL Policies, used by Sandworm to mass-deploy wipers via GPO.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.execution
    - attack.t1484.001
    - attack.impact
    - attack.t1485
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\\SYSVOL\\'
        TargetFilename|contains|all:
            - '\\Policies\\'
    selection_ext:
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.ps1'
            - '.bat'
            - '\\ScheduledTasks.xml'
    condition: selection and selection_ext
falsepositives:
    - Deploy legítimo de software via GPO (validar janela de mudança)
level: high
"""],
  why="A distribuição de wipers via GPO é um comportamento estrutural observado em várias campanhas (Industroyer2, Prestige). Monitorar escrita em SYSVOL é de baixo volume e alto sinal.",
  extra_kql="""DeviceFileEvents
| where FolderPath has @"\\SYSVOL\\" and FolderPath has @"\\Policies\\"
| where FileName endswith ".exe" or FileName endswith ".ps1" or FileName endswith ".bat" or FileName =~ "ScheduledTasks.xml"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256""",
  extra_spl="""index=sysmon EventCode=11 TargetFilename="*\\SYSVOL\\*\\Policies\\*" (TargetFilename="*.exe" OR TargetFilename="*.ps1" OR TargetFilename="*.bat" OR TargetFilename="*ScheduledTasks.xml")
| table _time host User Image TargetFilename""",
  gaps="Controladores de domínio frequentemente sem Sysmon/EDR; ambientes OT sem logging de host; wipers que exploram drivers legítimos (EaseUS/ElRawDisk) geram pouca telemetria antes do impacto."),

 dict(mitre="G0010", title="Turla / Snake / Secret Blizzard (RU-FSB)",
  ttp="Implants furtivos (Snake, Kazuar, ComRAT, TinyTurla), hijacking de infraestrutura de outros atores, C2 via satélite, persistência como serviço.",
  telemetry=["System EID 7045 / Security 4697", "Sysmon EID 13 (registro de serviços)", "DNS/Proxy", "Memória (Volatility) para hunts"],
  sigma=["""title: Service Installed With Binary In Unusual Path (svchost-hosted DLL)
id: 7c2d9e41-5a6b-4c3d-8e1f-0a9b8c7d6e06
status: experimental
description: New service whose ImagePath references svchost with a ServiceDll outside System32 - technique used by TinyTurla and similar backdoors.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1543.003
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\\Services\\'
        TargetObject|endswith: '\\Parameters\\ServiceDll'
    filter_system:
        Details|startswith:
            - 'C:\\Windows\\System32\\'
            - '%SystemRoot%\\System32\\'
            - '%systemroot%\\system32\\'
    condition: selection and not filter_system
falsepositives:
    - Softwares de terceiros que registram ServiceDll própria (raro)
level: high
"""],
  why="Turla usa malwares diversos, mas a persistência como DLL de serviço hospedada em svchost é recorrente. A regra mira o local anômalo da DLL, não hashes.",
  extra_kql="""DeviceRegistryEvents
| where RegistryKey has @"\\Services\\" and RegistryValueName == "ServiceDll"
| where not(RegistryValueData startswith @"C:\\Windows\\System32\\" or RegistryValueData startswith "%SystemRoot%")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName""",
  extra_spl="""index=sysmon EventCode=13 TargetObject="*\\Services\\*\\Parameters\\ServiceDll" NOT (Details="C:\\Windows\\System32\\*" OR Details="%SystemRoot%*")
| table _time host Image TargetObject Details""",
  gaps="DLL colocada dentro de System32 (TinyTurla usou w64time.dll) burla o filtro – complementar com verificação de assinatura; Snake opera em kernel e cifra comunicação P2P."),

 dict(mitre="G0032", title="Lazarus Group / Diamond Sleet (KP-RGB)",
  ttp="Engenharia social (falsas vagas – Operation DreamJob), trojanização de apps (3CX, trading apps), roubo de criptoativos, exploração de Log4j/ManageEngine, DLL side-loading.",
  telemetry=["Sysmon EID 1/7 (image load) ou DeviceImageLoadEvents", "Telemetria de e-mail/LinkedIn (cloud app)", "EDR macOS (ESF) para alvos de cripto"],
  sigma=["""title: Signed Binary Loading DLL From User-Writable Path (Side-Loading)
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c07
status: experimental
description: Microsoft-signed or vendor executables running from user profile/ProgramData loading unsigned DLLs, pattern seen in Lazarus DreamJob payloads.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.defense-evasion
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_path:
        Image|contains:
            - '\\AppData\\'
            - '\\ProgramData\\'
            - '\\Users\\Public\\'
        ImageLoaded|contains:
            - '\\AppData\\'
            - '\\ProgramData\\'
            - '\\Users\\Public\\'
    selection_unsigned:
        Signed: 'false'
    condition: all of selection_*
falsepositives:
    - Aplicações de usuário (Teams, Slack, atualizadores) – criar allowlist por Image
level: medium
"""],
  why="O side-loading a partir de pastas graváveis é o mecanismo de execução mais estável nas campanhas DreamJob; requer baseline/allowlist para baixo FP.",
  extra_kql="""DeviceImageLoadEvents
| where InitiatingProcessFolderPath has_any (@"\\AppData\\", @"\\ProgramData\\", @"\\Users\\Public\\")
| where FolderPath has_any (@"\\AppData\\", @"\\ProgramData\\", @"\\Users\\Public\\")
| join kind=leftanti (DeviceFileCertificateInfo | where IsSigned == true | project SHA1) on SHA1
| summarize count() by InitiatingProcessFileName, FileName, FolderPath""",
  extra_spl="""index=sysmon EventCode=7 Signed=false (Image="*\\AppData\\*" OR Image="*\\ProgramData\\*") (ImageLoaded="*\\AppData\\*" OR ImageLoaded="*\\ProgramData\\*")
| stats count by Image ImageLoaded host""",
  gaps="EID 7 é volumoso e frequentemente desativado; DLLs assinadas com certificados roubados contornam o filtro; payloads em macOS/Linux exigem telemetria própria."),

 dict(mitre="G0094", title="Kimsuky / Emerald Sleet / APT43 (KP)",
  ttp="Spearphishing com LNK/CHM/HWP, macros e scripts VBS/PowerShell, AppleSeed/BabyShark, coleta de credenciais via páginas falsas, uso de mshta.",
  telemetry=["Sysmon EID 1 (linha de comando)", "Proxy/DNS", "Gateway de e-mail (anexos LNK/CHM)"],
  sigma=["""title: MSHTA Or HH Spawning Script Interpreter From Document Lure
id: 3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e08
status: experimental
description: mshta.exe or hh.exe (CHM) spawning powershell/cmd/wscript - common Kimsuky execution chain from LNK/CHM lures.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.execution
    - attack.t1218.005
    - attack.t1218.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\mshta.exe'
            - '\\hh.exe'
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\curl.exe'
    condition: selection
falsepositives:
    - Aplicações legadas HTA internas
level: high
"""],
  why="Proxy execution via binários assinados (LOLBins) é central para Kimsuky; a relação pai→filho é estável mesmo com mudanças de payload.",
  extra_kql="""DeviceProcessEvents
| where InitiatingProcessFileName in~ ("mshta.exe","hh.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (ParentImage="*\\mshta.exe" OR ParentImage="*\\hh.exe") (Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\curl.exe")
| table _time host ParentCommandLine CommandLine""",
  gaps="Execução via HWP (Hangul) e cadeias em macOS não são cobertas; renomear mshta.exe exige uso de OriginalFileName."),

 dict(mitre="G0096", title="APT41 / Winnti / Brass Typhoon (CN)",
  ttp="Dupla motivação (espionagem + financeiro); exploração de aplicações web públicas (Citrix, ManageEngine, Log4j), webshells, supply chain, rootkits, uso de certificados roubados.",
  telemetry=["Logs de servidor web/WAF", "Sysmon EID 1 em servidores IIS/Tomcat", "DeviceProcessEvents", "Telemetria de certificados de código"],
  sigma=["""title: Web Server Process Spawning Shell Or Recon Commands (Webshell)
id: 5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a09
status: experimental
description: IIS/Tomcat/Java worker processes spawning command interpreters or recon utilities - typical post-exploitation of public-facing apps by APT41, Volt Typhoon, HAFNIUM.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.initial-access
    - attack.t1190
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\tomcat.exe'
            - '\\tomcat8.exe'
            - '\\tomcat9.exe'
            - '\\java.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\UMWorkerProcess.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\whoami.exe'
            - '\\net.exe'
            - '\\net1.exe'
            - '\\nltest.exe'
            - '\\certutil.exe'
            - '\\rundll32.exe'
    condition: all of selection_*
falsepositives:
    - Aplicações Java que executam scripts de manutenção (baseline por servidor)
level: high
"""],
  why="Independente do CVE explorado, a pós-exploração de apps web gera processos filhos anômalos do worker web – ponto de estrangulamento comum a vários grupos chineses.",
  extra_kql="""DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","tomcat9.exe","java.exe","httpd.exe","nginx.exe","UMWorkerProcess.exe")
| where FileName in~ ("cmd.exe","powershell.exe","whoami.exe","net.exe","net1.exe","nltest.exe","certutil.exe","rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (ParentImage="*\\w3wp.exe" OR ParentImage="*\\java.exe" OR ParentImage="*\\tomcat*.exe" OR ParentImage="*\\UMWorkerProcess.exe") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe" OR Image="*\\net*.exe" OR Image="*\\nltest.exe" OR Image="*\\certutil.exe")
| table _time host ParentImage CommandLine""",
  gaps="Webshells em memória (.NET assembly load, Godzilla) não geram processo filho; appliances de borda (Citrix, Ivanti, Fortinet) não suportam EDR – depender de logs do appliance e NetFlow."),

 dict(mitre="G1017", title="Volt Typhoon (CN) – pré-posicionamento em infraestrutura crítica",
  ttp="Living-off-the-land puro: ntdsutil, netsh portproxy, wmic, PowerShell; exploração de dispositivos de borda (Fortinet, Ivanti, Versa) e redes KV-botnet de SOHO.",
  telemetry=["Security EID 4688 com command line", "Sysmon EID 1", "Logs de dispositivos de borda", "Zeek/NetFlow"],
  sigma=["""title: NTDS.dit Extraction Via Ntdsutil IFM Or Volume Shadow Copy
id: 6f7a8b9c-0d1e-4f2a-3b4c-5d6e7f8a9b10
status: stable
description: ntdsutil 'ifm' or vssadmin shadow creation used to dump AD database - core Volt Typhoon credential access TTP (CISA AA24-038A).
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_ntdsutil:
        Image|endswith: '\\ntdsutil.exe'
        CommandLine|contains: 'ifm'
    selection_vss:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
            - 'create'
            - 'shadow'
    condition: 1 of selection_*
falsepositives:
    - Backups de AD conduzidos por administradores
level: high
""", """title: Netsh PortProxy Rule Added (Internal Pivot)
id: 7a8b9c0d-1e2f-4a3b-4c5d-6e7f8a9b0c11
status: stable
description: netsh interface portproxy add v4tov4 - used by Volt Typhoon and others to tunnel traffic through compromised hosts.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.command-and-control
    - attack.t1090.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\netsh.exe'
        CommandLine|contains|all:
            - 'portproxy'
            - 'add'
    condition: selection
falsepositives:
    - Configurações administrativas raras (documentar)
level: high
"""],
  why="Volt Typhoon evita malware; a única forma confiável é detectar abuso de ferramentas nativas com argumentos específicos. Ambas as regras têm volume baixíssimo em ambientes saudáveis.",
  extra_kql="""DeviceProcessEvents
| where (FileName =~ "ntdsutil.exe" and ProcessCommandLine has "ifm")
   or (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("create","shadow"))
   or (FileName =~ "netsh.exe" and ProcessCommandLine has_all ("portproxy","add"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine""",
  extra_spl="""index=wineventlog (EventCode=4688 OR source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) ((Image="*\\ntdsutil.exe" CommandLine="*ifm*") OR (Image="*\\vssadmin.exe" CommandLine="*create*shadow*") OR (Image="*\\netsh.exe" CommandLine="*portproxy*add*"))
| table _time host user CommandLine""",
  gaps="EID 4688 sem 'Include command line' torna as regras inúteis; atividade em dispositivos de borda (sem EDR) e uso de credenciais válidas via RDP passam despercebidos; limpeza de logs (wevtutil cl)."),

 dict(mitre="G0045", title="APT10 / menuPass / Stone Panda (CN-MSS)",
  ttp="Comprometimento de MSPs (Cloud Hopper), DLL side-loading (PlugX, QuasarRAT, SodaMaster), uso de credenciais de prestadores, staging com RAR.",
  telemetry=["Logs de VPN/PAM de terceiros", "Sysmon EID 1/7", "DLP / volume de saída"],
  sigma=["""title: Data Staging With RAR Using Password And Archive Splitting
id: 8b9c0d1e-2f3a-4b4c-5d6e-7f8a9b0c1d12
status: experimental
description: rar/winrar command line with password (-hp/-p) and volume splitting (-v), used by APT10 and many espionage actors to stage exfiltration.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
            - '\\rar.exe'
            - '\\winrar.exe'
        - OriginalFileName: 'Command line RAR'
    selection_args:
        CommandLine|contains:
            - ' -hp'
            - ' -p'
    selection_split:
        CommandLine|contains: ' -v'
    condition: selection_img and selection_args and selection_split
falsepositives:
    - Backups manuais por usuários avançados
level: medium
"""],
  why="A compactação cifrada e fatiada antes da exfiltração é uma etapa quase obrigatória em operações de espionagem, independente do implant.",
  extra_kql="""DeviceProcessEvents
| where FileName in~ ("rar.exe","winrar.exe") or ProcessVersionInfoOriginalFileName == "Command line RAR"
| where ProcessCommandLine has_any (" -hp"," -p") and ProcessCommandLine has " -v"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (Image="*\\rar.exe" OR Image="*\\winrar.exe") (CommandLine="* -hp*" OR CommandLine="* -p*") CommandLine="* -v*"
| table _time host User CommandLine""",
  gaps="Uso de 7-Zip, makecab ou compressão nativa PowerShell (Compress-Archive) exige regras irmãs; acesso via conta de MSP legítima é difícil de distinguir sem UEBA."),

 dict(mitre="G0049", title="OilRig / APT34 / Hazel Sandstorm (IR-MOIS)",
  ttp="Backdoors com C2 sobre DNS (DNSpionage, Saitama) e e-mail/EWS, webshells em Exchange, roubo de credenciais via filtros de senha (password filter DLL).",
  telemetry=["DNS query logs (Sysmon EID 22, servidores DNS, Zeek)", "Registro HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "Exchange IIS logs"],
  sigma=["""title: New LSA Password Filter / Notification Package Registered
id: 9c0d1e2f-3a4b-4c5d-6e7f-8a9b0c1d2e13
status: experimental
description: Modification of LSA 'Notification Packages' to load a password filter DLL capturing plaintext passwords - used by OilRig/APT34.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.credential-access
    - attack.t1556.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\\Control\\Lsa\\Notification Packages'
    condition: selection
falsepositives:
    - Soluções de sincronização de senha (ex.: Azure AD Password Protection, PCNS) – allowlist
level: high
"""],
  why="Filtros de senha em DCs dão acesso a credenciais em texto claro com persistência; alterações na chave são raríssimas.",
  extra_kql="""DeviceRegistryEvents
| where RegistryKey endswith @"\\Control\\Lsa" and RegistryValueName == "Notification Packages"
| project Timestamp, DeviceName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName""",
  extra_spl="""index=sysmon (EventCode=13) TargetObject="*\\Control\\Lsa\\Notification Packages"
| table _time host Image Details""",
  gaps="Tunelamento DNS requer análise estatística (entropia/tamanho de label), não coberta por Sigma simples; DCs sem Sysmon."),

 dict(mitre="G0069", title="MuddyWater / Mango Sandstorm (IR-MOIS)",
  ttp="Spearphishing com links para instaladores de RMM legítimos (Atera, ScreenConnect, SimpleHelp, AnyDesk), PowerShell ofuscado, PowGoop.",
  telemetry=["Inventário de software / DeviceProcessEvents", "Proxy (domínios de RMM)", "Gateway de e-mail (links para file-sharing)"],
  sigma=["""title: Remote Monitoring And Management Tool Execution From Download Folder
id: 0d1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f14
status: experimental
description: RMM agents (Atera, ScreenConnect, SimpleHelp, AnyDesk, Syncro, NetBird) launched from user Downloads/Temp - MuddyWater initial access pattern.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        - Image|contains:
            - 'AteraAgent'
            - 'ScreenConnect'
            - 'SimpleHelp'
            - 'AnyDesk'
            - 'Syncro'
            - 'netbird'
        - Product|contains:
            - 'Atera'
            - 'ScreenConnect'
            - 'SimpleHelp'
            - 'AnyDesk'
    selection_path:
        Image|contains:
            - '\\Downloads\\'
            - '\\AppData\\Local\\Temp\\'
    condition: all of selection_*
falsepositives:
    - Suporte técnico legítimo; manter allowlist das ferramentas RMM aprovadas
level: medium
"""],
  why="O grupo abusa de software legítimo; o sinal é a execução de RMM não sancionado a partir de pastas de download do usuário.",
  extra_kql="""DeviceProcessEvents
| where FolderPath has_any (@"\\Downloads\\", @"\\AppData\\Local\\Temp\\")
| where ProcessVersionInfoProductName has_any ("Atera","ScreenConnect","SimpleHelp","AnyDesk") or FileName has_any ("AteraAgent","ScreenConnect","SimpleHelp","AnyDesk")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName""",
  extra_spl="""index=sysmon EventCode=1 (Image="*\\Downloads\\*" OR Image="*\\AppData\\Local\\Temp\\*") (Image="*Atera*" OR Image="*ScreenConnect*" OR Image="*SimpleHelp*" OR Image="*AnyDesk*" OR Product="*Atera*")
| table _time host User Image""",
  gaps="Se a organização já usa a mesma RMM, a detecção depende de tenant/ID de instância (campo não presente no processo); instalação em Program Files contorna o filtro de caminho."),

 dict(mitre="G0059", title="Magic Hound / APT35 / Charming Kitten / Mint Sandstorm (IR-IRGC)",
  ttp="Phishing de credenciais sofisticado (inclusive MFA), exploração de Exchange ProxyShell e Log4j, PowerShell CharmPower, criação de contas locais.",
  telemetry=["Security EID 4720/4732", "IIS/Exchange logs", "Entra ID Identity Protection"],
  sigma=["""title: Local Account Created And Added To Administrators Via Net Command
id: 1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a15
status: experimental
description: net user /add followed by localgroup administrators /add - persistence observed after APT35 ProxyShell exploitation.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\\net.exe'
            - '\\net1.exe'
    selection_add:
        CommandLine|contains|all:
            - 'localgroup'
            - 'admin'
            - '/add'
    condition: all of selection_*
falsepositives:
    - Scripts de provisionamento de TI
level: medium
"""],
  why="Contas locais administrativas criadas por linha de comando em servidores expostos são um forte indicador de pós-exploração.",
  extra_kql="""DeviceProcessEvents
| where FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_all ("localgroup","admin","/add")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*localgroup*" CommandLine="*admin*" CommandLine="*/add*"
| table _time host User ParentImage CommandLine""",
  gaps="Criação via API (NetUserAdd) ou PowerShell New-LocalUser não usa net.exe – correlacionar com EID 4720; phishing de credenciais ocorre fora do perímetro."),

 dict(mitre="G0046", title="FIN7 / Carbon Spider / Sangria Tempest (cibercrime)",
  ttp="Phishing com JS/LNK, Carbanak/Lizar, PowerShell, uso de ferramentas de pentest (Cobalt Strike), parceria com operações de ransomware (Darkside/BlackMatter/ALPHV).",
  telemetry=["Sysmon EID 1/3", "AMSI/ScriptBlock (EID 4104)", "Proxy"],
  sigma=["""title: Encoded PowerShell Spawned By Script Host
id: 2f3a4b5c-6d7e-4f8a-9b0c-1d2e3f4a5b16
status: experimental
description: wscript/cscript/mshta spawning powershell with -enc/-EncodedCommand - FIN7 JavaScript loader chains.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
    selection_child:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc'
            - ' -EncodedCommand'
            - ' -e '
    condition: all of selection_*
falsepositives:
    - Scripts de login legados
level: high
"""],
  why="A cadeia script host → PowerShell codificado é estável entre famílias de loaders usadas por FIN7.",
  extra_kql="""DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","mshta.exe") and FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\\s-(e|enc|encodedcommand)\\s"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe") Image="*\\powershell.exe" (CommandLine="* -enc*" OR CommandLine="* -EncodedCommand*" OR CommandLine="* -e *")
| table _time host User CommandLine""",
  gaps="Uso de pwsh.exe, PowerShell sem powershell.exe (System.Management.Automation in-process) ou abreviações (-ec) exigem variações."),

 dict(mitre="G0047", title="Gamaredon / Primitive Bear / Aqua Blizzard (RU-FSB Crimea)",
  ttp="Volume massivo de phishing com documentos que usam remote template injection, VBS/HTA ofuscados, propagação por USB (LNK), C2 por fast-flux e Telegram.",
  telemetry=["Sysmon EID 1/3/11", "Proxy (requisições de .dot remotos)", "Monitoramento de mídia removível"],
  sigma=["""title: Office Application Spawning Script Interpreter Or LOLBin
id: 3a4b5c6d-7e8f-4a9b-0c1d-2e3f4a5b6c17
status: stable
description: WINWORD/EXCEL spawning wscript/mshta/powershell - Gamaredon template-injection and macro chains.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense-evasion
    - attack.t1221
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
        Image|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
            - '\\powershell.exe'
            - '\\cmd.exe'
    condition: selection
falsepositives:
    - Add-ins corporativos legados
level: high
"""],
  why="Regra clássica de altíssimo retorno; Gamaredon mantém o padrão por anos devido ao volume de campanhas.",
  extra_kql="""DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("wscript.exe","cscript.exe","mshta.exe","powershell.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.EXE") (Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\cmd.exe")
| table _time host User CommandLine""",
  gaps="ASR rules podem bloquear antes do log; execução via WMI (pai = WmiPrvSE) quebra a relação pai-filho; o template remoto é visível apenas no proxy."),

 dict(mitre="G1015", title="Scattered Spider / Octo Tempest / UNC3944 (cibercrime)",
  ttp="Engenharia social de help desk (reset de MFA), SIM swapping, federação maliciosa de domínio no Entra ID, abuso de RMM, ransomware ALPHV/DragonForce.",
  telemetry=["Entra ID AuditLogs (Set domain authentication / Add unverified domain)", "Logs de ITSM/help desk", "Registro de métodos MFA"],
  sigma=["""title: Domain Federation Settings Modified In Entra ID
id: 4b5c6d7e-8f9a-4b0c-1d2e-3f4a5b6c7d18
status: experimental
description: Changes to domain federation/authentication used by Scattered Spider (and APT29) to add attacker-controlled IdP for persistence.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1484.002
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName:
            - 'Set domain authentication'
            - 'Set federation settings on domain'
            - 'Add unverified domain'
    condition: selection
falsepositives:
    - Projetos de migração de IdP
level: high
"""],
  why="Federação maliciosa permite emitir tokens para qualquer usuário; evento raro de controle-plane.",
  extra_kql="""AuditLogs
| where OperationName in ("Set domain authentication","Set federation settings on domain","Add unverified domain")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources""",
  extra_spl="""index=azure sourcetype=azure:aad:audit (operationName="Set domain authentication" OR operationName="Set federation settings on domain" OR operationName="Add unverified domain")
| table _time operationName initiatedBy.user.userPrincipalName targetResources{}.displayName""",
  gaps="A fase de engenharia social (ligação ao help desk) não gera log técnico; registrar e auditar resets de MFA no ITSM é imprescindível."),

 dict(mitre="G0050", title="APT32 / OceanLotus (VN)",
  ttp="Watering holes, documentos com macros, persistência por scheduled tasks com COM hijacking, Cobalt Strike, alvo em empresas estrangeiras no Vietnã e dissidentes.",
  telemetry=["Security EID 4698 / Sysmon EID 1", "TaskScheduler/Operational", "Proxy"],
  sigma=["""title: Scheduled Task Created With Executable In User-Writable Location
id: 5c6d7e8f-9a0b-4c1d-2e3f-4a5b6c7d8e19
status: experimental
description: schtasks /create pointing to AppData/ProgramData/Public - persistence used by APT32 and many other actors.
author: CTI Consolidation
date: 2025-01-01
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    selection_path:
        CommandLine|contains:
            - '\\AppData\\'
            - '\\ProgramData\\'
            - '\\Users\\Public\\'
            - '%APPDATA%'
            - '%PROGRAMDATA%'
    condition: all of selection_*
falsepositives:
    - Atualizadores de software de usuário (Chrome/Teams) – allowlist por nome de tarefa
level: medium
"""],
  why="Persistência por tarefa agendada apontando para diretórios graváveis é comum; com allowlist o FP é controlável.",
  extra_kql="""DeviceProcessEvents
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (@"\\AppData\\", @"\\ProgramData\\", @"\\Users\\Public\\", "%APPDATA%", "%PROGRAMDATA%")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine""",
  extra_spl="""index=sysmon EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*" (CommandLine="*\\AppData\\*" OR CommandLine="*\\ProgramData\\*" OR CommandLine="*\\Users\\Public\\*")
| table _time host User CommandLine""",
  gaps="Criação via COM/API (ITaskService) não usa schtasks.exe – usar EID 4698 com conteúdo XML da tarefa."),
]
