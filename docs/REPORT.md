# APT Threat Map – relatório de inteligência e engenharia de detecção
_Gerado em 10/11/2026. Artefato principal: `APT_Threat_Map.html` (offline, único arquivo)._

## 1. Resumo executivo
- **1.451 grupos/entidades** consolidados de **14 fontes** (MITRE ATT&CK, ThaiCERT/ETDA, MISP, Malpedia, **APTmap**, **Google Cloud/Mandiant**, **Wikipedia**, BRANDEFENSE, EternalLiberty, Microsoft/CrowdStrike, SigmaHQ, APTMalware e as planilhas fornecidas).
- 174 grupos com TTPs ATT&CK documentadas; 773 corroborados por ≥3 fontes; 747 com origem geolocalizada; 2.445 ferramentas/malware (695 casadas a software ATT&CK).
- 515 técnicas usadas por grupos → cobertura do catálogo: **● 428 com regra** (inclui sub-técnicas cobertas por regra da técnica-pai), ◐ 16 parcial (ASR/D3FEND-Detect), ○ 71 lacunas.
- 866 regras Sigma convertidas para 8 linguagens (Splunk, Elastic Lucene/EQL/ES|QL, OpenSearch, QRadar AQL, Stellar Cyber, Defender XDR KQL).
- Traçagem completa por técnica: Defender (tabelas + 19 regras ASR) → 146 contramedidas D3FEND → data components DeTT&CT → 216 ações RE&CT.

## 2. Cadeia de traçagem implementada
```mermaid
flowchart LR
  G[Grupo APT<br/>origem · vitimologia · setores] --> A[Artefato / ferramenta<br/>software ATT&CK · APTmap · planilha]
  G --> T
  A --> T[Técnica ATT&CK<br/>procedimento do grupo]
  T --> M[Microsoft Defender<br/>tabelas AH · ASR · KQL]
  T --> D[MITRE D3FEND<br/>contramedida ↔ artefato digital]
  T --> X[DeTT&CT<br/>data components · YAML]
  T --> R[RE&CT<br/>ações por estágio · playbook]
  T --> S[Detecções<br/>Sigma→SPL/Lucene/EQL/ES|QL/AQL/Stellar/KQL]
```
Cada elo é navegável no HTML (aba **Traçagem**: clique numa técnica, ferramenta ou contramedida para destacar o caminho) e exportável (Navigator, DeTT&CT, RE&CT, Sigma, consultas por SIEM, CSV).

## 3. Lógica de Threat Intelligence aplicada
| Elemento | Lógica |
|---|---|
| Deduplicação | aliases normalizados (sem pontuação/sufixos group/team/gang/crew), ID MITRE com precedência, sem fusão transitiva; APTmap só por nome principal/ID |
| Confiança do registro | corroboração (nº de fontes independentes) + presença no ATT&CK + confiança de atribuição do APTmap |
| Similaridade | cosseno TF-IDF sobre técnicas ∪ ferramentas (≥0,22) → sobreposição de tradecraft/duplicidade de nomenclatura (não é atribuição) |
| Relações declaradas | MISP/APTmap (similar, overlaps, related-to, subgroup…) com linguagem estimativa (likely/very-likely) |
| Relevância (TID) | W = (w_setor·[setor] + w_país·[país]) × (0,5 + 0,5·min(1,fontes/8) + 0,15·[ATT&CK]); P(t) = Σ W normalizado 0–100 |
| Lacunas | técnicas priorizadas sem regra, separando pré-ataque (recon/recursos → monitoramento externo) |

## 4. Panorama global
| Origem (atribuição) | Grupos | | País mais visado | Grupos | | Setor mais visado | Grupos |
|---|---|---|---|---|---|---|---|
| China | 307 | | United States | 192 | | Governo | 260 |
| Russian Federation | 165 | | United Kingdom | 119 | | Defesa/Militar | 158 |
| Iran | 80 | | India | 113 | | Tecnologia/TI | 150 |
| North Korea | 24 | | Germany | 110 | | Financeiro | 144 |
| India | 17 | | Russian Federation | 104 | | Indústria/Manufatura | 132 |
| Israel | 13 | | China | 100 | | Educação/Pesquisa | 131 |
| Türkiye | 12 | | South Korea | 86 | | Energia/Utilities | 128 |
| Ukraine | 11 | | Thailand | 83 | | Telecom | 125 |
| Brazil | 11 | | Japan | 82 | | Saúde/Farma | 121 |
| United States | 10 | | Canada | 79 | | Mídia/Entretenimento | 101 |
| Pakistan | 10 | | Taiwan | 79 | | Transporte/Logística | 85 |
| Palestine, State of | 8 | | Türkiye | 73 | | ONGs/Sociedade civil | 83 |

### Técnicas mais usadas (todos os grupos) e cobertura
| Técnica | Nome | Grupos | Cobertura | Regras | ASR | D3FEND |
|---|---|---|---|---|---|---|
| T1105 | Ingress Tool Transfer | 90 | ● | 3 | 2 | 11 |
| T1204.002 | Malicious File | 87 | ● | 4 | 7 | 15 |
| T1059.001 | PowerShell | 86 | ● | 4 | 2 | 15 |
| T1588.002 | Tool | 84 | ● | 3 | 0 | 0 |
| T1566.001 | Spearphishing Attachment | 79 | ● | 3 | 3 | 31 |
| T1059.003 | Windows Command Shell | 73 | ● | 3 | 0 | 15 |
| T1036.005 | Match Legitimate Resource Name or Location | 66 | ● | 3 | 2 | 13 |
| T1082 | System Information Discovery | 59 | ● | 3 | 0 | 7 |
| T1547.001 | Registry Run Keys / Startup Folder | 59 | ● | 3 | 0 | 18 |
| T1071.001 | Web Protocols | 58 | ● | 3 | 0 | 23 |
| T1053.005 | Scheduled Task | 55 | ● | 4 | 0 | 16 |
| T1083 | File and Directory Discovery | 52 | ● | 3 | 0 | 11 |
| T1204.001 | Malicious Link | 50 | ● | 3 | 0 | 15 |
| T1078 | Valid Accounts | 49 | ● | 3 | 0 | 9 |
| T1070.004 | File Deletion | 48 | ● | 3 | 0 | 11 |
| T1566.002 | Spearphishing Link | 48 | ● | 2 | 0 | 34 |
| T1583.001 | Domains | 48 | ○ | 0 | 0 | 0 |
| T1005 | Data from Local System | 47 | ● | 3 | 0 | 11 |
| T1190 | Exploit Public-Facing Application | 47 | ● | 4 | 0 | 14 |
| T1059.005 | Visual Basic | 46 | ● | 3 | 4 | 15 |
| T1016 | System Network Configuration Discovery | 45 | ● | 3 | 0 | 19 |
| T1003.001 | LSASS Memory | 44 | ● | 3 | 1 | 12 |
| T1018 | Remote System Discovery | 43 | ● | 3 | 0 | 27 |
| T1047 | Windows Management Instrumentation | 43 | ● | 3 | 1 | 17 |
| T1057 | Process Discovery | 42 | ● | 3 | 0 | 6 |

### Backlog de engenharia de detecção (lacunas com mais grupos, excluindo pré-ataque)
| Técnica | Nome | Grupos | Data components necessários | Defender (tabelas) |
|---|---|---|---|---|
| T1657 | Financial Theft | 19 | Logon Session Creation, Process Creation, Command Execution, Application Log Content | DeviceLogonEvents, IdentityLogonEvents, DeviceProcessEvents |
| T1684.001 | Impersonation | 18 | Logon Session Creation, Application Log Content, Command Execution | DeviceLogonEvents, IdentityLogonEvents, CloudAppEvents |
| T1680 | Local Storage Discovery | 10 | Process Creation, Command Execution, User Account Authentication | DeviceProcessEvents, DeviceEvents:PowerShellCommand, IdentityLogonEvents |
| T1530 | Data from Cloud Storage | 6 | Cloud Storage Access, User Account Metadata, Network Traffic Content, User Account Authentication | CloudAppEvents, IdentityInfo, DeviceNetworkEvents:*ConnectionInspected |
| T1080 | Taint Shared Content | 5 | File Creation, Network Share Access, File Modification | DeviceFileEvents:FileCreated, DeviceFileEvents (RequestProtocol=SMB), DeviceNetworkEvents |
| T1480 | Execution Guardrails | 5 | Process Creation, User Account Authentication, Logon Session Creation, Network Connection Creation | DeviceProcessEvents, IdentityLogonEvents, DeviceLogonEvents |
| T1654 | Log Enumeration | 5 | Process Creation, File Access, Command Execution | DeviceProcessEvents, DeviceFileEvents (parcial), DeviceEvents:PowerShellCommand |
| T1025 | Data from Removable Media | 4 | File Access, Drive Creation, Process Creation | DeviceFileEvents (parcial), DeviceEvents:PnpDeviceConnected, DeviceProcessEvents |
| T1111 | Multi-Factor Authentication Interception | 4 | Process Access, Logon Session Creation, Windows Registry Key Modification, Driver Load | DeviceEvents:OpenProcessApiCall, DeviceLogonEvents, IdentityLogonEvents |
| T1678 | Delay Execution | 4 | Process Creation, Module Load, Script Execution | DeviceProcessEvents, DeviceImageLoadEvents, DeviceEvents:PowerShellCommand |
| T1610 | Deploy Container | 3 | Application Log Content, Container Start, Process Creation, Network Traffic Content | CloudAppEvents, DeviceProcessEvents, DeviceNetworkEvents:*ConnectionInspected |
| T1052.001 | Exfiltration over USB | 2 | Process Creation, File Creation, File Access, Drive Creation | DeviceProcessEvents, DeviceFileEvents:FileCreated, DeviceFileEvents (parcial) |
| T1480.001 | Environmental Keying | 2 | Logon Session Creation, Process Creation, Network Connection Creation, Module Load | DeviceLogonEvents, IdentityLogonEvents, DeviceProcessEvents |
| T1480.002 | Mutual Exclusion | 2 | Process Creation, File Creation, File Access, Process Termination | DeviceProcessEvents, DeviceFileEvents:FileCreated, DeviceFileEvents (parcial) |
| T1491.002 | External Defacement | 2 | File Modification, Network Traffic Content, Process Creation, Logon Session Metadata | DeviceFileEvents:FileModified, DeviceFileEvents:FileRenamed, DeviceNetworkEvents:*ConnectionInspected |
| T1599 | Network Boundary Bridging | 2 | Network Traffic Flow, Network Traffic Content | DeviceNetworkEvents, DeviceNetworkEvents:*ConnectionInspected |
| T1614 | System Location Discovery | 2 | Process Creation, OS API Execution, Command Execution, Network Traffic Content | DeviceProcessEvents, DeviceEvents:*ApiCall, DeviceEvents:PowerShellCommand |
| T1651 | Cloud Administration Command | 2 | Command Execution, Script Execution, Process Creation | DeviceProcessEvents, DeviceEvents:PowerShellCommand, DeviceEvents:AmsiScriptDetection |
| T1665 | Hide Infrastructure | 2 | Network Connection Creation, Domain Registration, Process Creation, Response Metadata | DeviceNetworkEvents, DeviceProcessEvents, DeviceNetworkEvents:*ConnectionInspected |
| T1677 | Poisoned Pipeline Execution | 2 | Cloud Service Modification, Cloud Service Metadata, Cloud Storage Access, File Metadata | CloudAppEvents, DeviceFileCertificateInfo, DeviceFileEvents |

### Onde investir (peso = nº de pares grupo×técnica cobertos)
| D3FEND (contramedida) | Tática | Peso | | ASR (Defender) | Peso | | Data component (DeTT&CT) | Peso |
|---|---|---|---|---|---|---|---|---|
| Content Quarantine (D3-CQ) | Isolate | 1978 | | Block all Office applications from creating child processes | 371 | | Process Creation | 3857 |
| File Encryption (D3-FE) | Harden | 1907 | | Block execution of potentially obfuscated scripts | 336 | | Command Execution | 1811 |
| File Analysis (D3-FA) | Detect | 1907 | | Block JavaScript or VBScript from launching downloaded executable content | 253 | | File Creation | 1452 |
| File Integrity Monitoring (D3-FIM) | Detect | 1907 | | Block executable files from running unless they meet a prevalence, age, or trusted list criterion | 224 | | Network Connection Creation | 1413 |
| Content Filtering (D3-CF) | Isolate | 1899 | | Block Office applications from creating executable content | 177 | | Network Traffic Content | 1001 |
| Content Modification (D3-CM) | Isolate | 1899 | | Block executable content from email client and webmail | 166 | | Network Traffic Flow | 914 |
| Local File Permissions (D3-LFP) | Isolate | 1840 | | Block Office communication application from creating child processes | 166 | | Module Load | 880 |
| Remote File Access Mediation (D3-RFAM) | Isolate | 1825 | | Block Adobe Reader from creating child processes | 129 | | File Access | 820 |
| Decoy File (D3-DF) | Deceive | 1780 | | Block process creations originating from PSExec and WMI commands | 87 | | Application Log Content | 652 |
| File Eviction (D3-FEV) | Evict | 1767 | | Block use of copied or impersonated system tools | 72 | | Windows Registry Key Modification | 576 |
| Restore File (D3-RF) | Restore | 1765 | | Block Win32 API calls from Office macros | 67 | | Process Access | 515 |
| Executable Allowlisting (D3-EAL) | Isolate | 1256 | | Block abuse of exploited vulnerable signed drivers | 55 | | File Modification | 477 |

## 5. Perfil de ameaça – Brasil (51 grupos com o Brasil na vitimologia)
| Grupo | Origem | ATT&CK | Motivação | Fontes | Técnicas |
|---|---|---|---|---|---|
| APT28 | Russian Federation | G0007 | Espionagem | 14 | 93 |
| APT29 | Russian Federation | G0016 | Espionagem | 14 | 66 |
| menuPass | China | G0045 | Espionagem | 14 | 46 |
| Gamaredon Group | Russian Federation | G0047 | Espionagem | 12 | 70 |
| Turla | Russian Federation | G0010 | Espionagem | 12 | 68 |
| Magic Hound | Iran | G0059 | Espionagem | 11 | 78 |
| Salt Typhoon | China | G1045 | Espionagem | 11 | 58 |
| Ke3chang | China | G0004 | Espionagem | 11 | 46 |
| Equation | United States | G0020 | Espionagem, Sabotagem/Destrutivo | 11 | 4 |
| AppleJeus | North Korea | G1049 | Espionagem, Financeiro | 11 | 2 |
| Lazarus Group | North Korea | G0032 | Espionagem, Financeiro, Sabotagem/Destrutivo | 10 | 93 |
| APT41 | China | G0096 | Espionagem, Financeiro | 10 | 82 |
| LAPSUS$ | Brazil | G1004 | Financeiro | 9 | 43 |
| Gorgon Group | Pakistan | G0078 | Espionagem, Financeiro | 9 | 16 |
| Carbanak | Ukraine | G0008 | Financeiro | 9 | 9 |
| Inception | Russian Federation | G0100 | Espionagem | 7 | 22 |
| Machete | Other | G0095 | Espionagem | 7 | 11 |
| Sowbug | Unknown | G0054 | Espionagem | 7 | 9 |
| Poseidon Group | Brazil | G0033 | Espionagem | 7 | 8 |
| Winnti Group | China | G0044 | Espionagem, Financeiro | 7 | 6 |

Técnicas mais frequentes entre os grupos que visam o Brasil:
| Técnica | Nome | Grupos | Cobertura |
|---|---|---|---|
| T1588.002 | Tool | 14 | ● |
| T1036.005 | Match Legitimate Resource Name or Location | 13 | ● |
| T1005 | Data from Local System | 12 | ● |
| T1105 | Ingress Tool Transfer | 12 | ● |
| T1059.001 | PowerShell | 11 | ● |
| T1059.003 | Windows Command Shell | 11 | ● |
| T1083 | File and Directory Discovery | 11 | ● |
| T1071.001 | Web Protocols | 10 | ● |
| T1547.001 | Registry Run Keys / Startup Folder | 10 | ● |
| T1057 | Process Discovery | 9 | ● |
| T1078 | Valid Accounts | 9 | ● |
| T1204.002 | Malicious File | 9 | ● |
| T1566.001 | Spearphishing Attachment | 9 | ● |
| T1082 | System Information Discovery | 9 | ● |
| T1056.001 | Keylogging | 7 | ● |

## 6. Possíveis sobreposições (similaridade TTP+ferramentas)
| Grupo A | Grupo B | Similaridade |
|---|---|---|
| Lotus Blossom | APT30 | 0.453 |
| Axiom | Elderwood | 0.355 |
| Naikon | Lotus Blossom | 0.335 |
| Rocke | TeamTNT | 0.305 |
| APT-C-36 | TA2541 | 0.301 |
| BlackByte | Medusa Group | 0.287 |
| ETHEREAL PANDA | Dalbit | 0.275 |
| Gorgon Group | TA2541 | 0.267 |
| Gorgon Group | Group5 | 0.264 |
| Aquatic Panda | Play | 0.262 |
| Inception | Confucius | 0.256 |
| Sidewinder | Confucius | 0.247 |
| Aquatic Panda | APT41 | 0.245 |
| Scattered Spider | LAPSUS$ | 0.243 |
| Mofang | Whitefly | 0.242 |

## 7. Matriz de conversão de regras (pySigma)
| Formato | OK | Fallback | Não suportado | Observação |
|---|---|---|---|---|
| splunk | 866 | 0 | 0 | sysmon + splunk_windows |
| elastic | 865 | 0 | 1 | Lucene + ecs_windows |
| eql | 865 | 0 | 1 | EQL + ecs_windows |
| esql | 817 | 0 | 49 | ES|QL (sem keywords livres) |
| opensearch | 865 | 0 | 1 | Lucene + ecs_windows |
| qradar | 539 | 298 | 29 | AQL fields; fallback = busca em payload |
| stellar | 865 | 0 | 1 | Lucene/DSL campos nativos (mapear p/ Interflow) |
| defender | 482 | 0 | 384 | KQL XDR (Device*/Identity*) |

## 8. Detecções dedicadas (grupos prioritários)
- **APT28 / Sofacy / Fancy Bear / Forest Blizzard (RU-GRU 26165)** (G0007) – regras: Outlook Initiating Outbound SMB/WebDAV to External Host (CVE-2023-23397 pattern); Password Spray Pattern - Many Accounts Failing From Single Source. Gaps: Sem Sysmon EID 3 ou MDE, a conexão do Outlook não é visível; tráfego via roteadores comprometidos (SOHO residencial) contorna listas de reputação; spray 'low and slow' abaixo do limiar.
- **APT29 / Cozy Bear / Midnight Blizzard (RU-SVR)** (G0016) – regras: Credentials Added To Service Principal Or Application; High-Privilege App Role Granted To Application (full_access_as_app / Mail.Read). Gaps: Licenciamento E5 necessário para MailItemsAccessed; uso de proxies residenciais; tokens roubados (pass-the-cookie) não geram falha de login; AD FS sem auditoria habilitada impede ver Golden SAML.
- **Sandworm Team / Seashell Blizzard (RU-GRU 74455)** (G0034) – regras: Scheduled Task Or Executable Dropped Into SYSVOL Policies. Gaps: Controladores de domínio frequentemente sem Sysmon/EDR; ambientes OT sem logging de host; wipers que exploram drivers legítimos (EaseUS/ElRawDisk) geram pouca telemetria antes do impacto.
- **Turla / Snake / Secret Blizzard (RU-FSB)** (G0010) – regras: Service Installed With Binary In Unusual Path (svchost-hosted DLL). Gaps: DLL colocada dentro de System32 (TinyTurla usou w64time.dll) burla o filtro – complementar com verificação de assinatura; Snake opera em kernel e cifra comunicação P2P.
- **Lazarus Group / Diamond Sleet (KP-RGB)** (G0032) – regras: Signed Binary Loading DLL From User-Writable Path (Side-Loading). Gaps: EID 7 é volumoso e frequentemente desativado; DLLs assinadas com certificados roubados contornam o filtro; payloads em macOS/Linux exigem telemetria própria.
- **Kimsuky / Emerald Sleet / APT43 (KP)** (G0094) – regras: MSHTA Or HH Spawning Script Interpreter From Document Lure. Gaps: Execução via HWP (Hangul) e cadeias em macOS não são cobertas; renomear mshta.exe exige uso de OriginalFileName.
- **APT41 / Winnti / Brass Typhoon (CN)** (G0096) – regras: Web Server Process Spawning Shell Or Recon Commands (Webshell). Gaps: Webshells em memória (.NET assembly load, Godzilla) não geram processo filho; appliances de borda (Citrix, Ivanti, Fortinet) não suportam EDR – depender de logs do appliance e NetFlow.
- **Volt Typhoon (CN) – pré-posicionamento em infraestrutura crítica** (G1017) – regras: NTDS.dit Extraction Via Ntdsutil IFM Or Volume Shadow Copy; Netsh PortProxy Rule Added (Internal Pivot). Gaps: EID 4688 sem 'Include command line' torna as regras inúteis; atividade em dispositivos de borda (sem EDR) e uso de credenciais válidas via RDP passam despercebidos; limpeza de logs (wevtutil cl).
- **APT10 / menuPass / Stone Panda (CN-MSS)** (G0045) – regras: Data Staging With RAR Using Password And Archive Splitting. Gaps: Uso de 7-Zip, makecab ou compressão nativa PowerShell (Compress-Archive) exige regras irmãs; acesso via conta de MSP legítima é difícil de distinguir sem UEBA.
- **OilRig / APT34 / Hazel Sandstorm (IR-MOIS)** (G0049) – regras: New LSA Password Filter / Notification Package Registered. Gaps: Tunelamento DNS requer análise estatística (entropia/tamanho de label), não coberta por Sigma simples; DCs sem Sysmon.
- **MuddyWater / Mango Sandstorm (IR-MOIS)** (G0069) – regras: Remote Monitoring And Management Tool Execution From Download Folder. Gaps: Se a organização já usa a mesma RMM, a detecção depende de tenant/ID de instância (campo não presente no processo); instalação em Program Files contorna o filtro de caminho.
- **Magic Hound / APT35 / Charming Kitten / Mint Sandstorm (IR-IRGC)** (G0059) – regras: Local Account Created And Added To Administrators Via Net Command. Gaps: Criação via API (NetUserAdd) ou PowerShell New-LocalUser não usa net.exe – correlacionar com EID 4720; phishing de credenciais ocorre fora do perímetro.
- **FIN7 / Carbon Spider / Sangria Tempest (cibercrime)** (G0046) – regras: Encoded PowerShell Spawned By Script Host. Gaps: Uso de pwsh.exe, PowerShell sem powershell.exe (System.Management.Automation in-process) ou abreviações (-ec) exigem variações.
- **Gamaredon / Primitive Bear / Aqua Blizzard (RU-FSB Crimea)** (G0047) – regras: Office Application Spawning Script Interpreter Or LOLBin. Gaps: ASR rules podem bloquear antes do log; execução via WMI (pai = WmiPrvSE) quebra a relação pai-filho; o template remoto é visível apenas no proxy.
- **Scattered Spider / Octo Tempest / UNC3944 (cibercrime)** (G1015) – regras: Domain Federation Settings Modified In Entra ID. Gaps: A fase de engenharia social (ligação ao help desk) não gera log técnico; registrar e auditar resets de MFA no ITSM é imprescindível.
- **APT32 / OceanLotus (VN)** (G0050) – regras: Scheduled Task Created With Executable In User-Writable Location. Gaps: Criação via COM/API (ITaskService) não usa schtasks.exe – usar EID 4698 com conteúdo XML da tarefa.

## 9. Arquivos entregues
| Arquivo | Conteúdo |
|---|---|
| `APT_Threat_Map.html` | Mapa 2D (coroplético origem/alvo, fluxos, painel por país), grafo de relacionamentos com filtros por tipo de relação e ego-rede, traçagem completa, priorização TID, catálogo de detecções em 9 formatos, matriz ATT&CK×cobertura, dossiês, fontes/metodologia |
| `APT_groups_consolidated.csv` | Grupos normalizados (origem ISO, motivação, setores canônicos, vítimas ISO, fontes, técnicas, ferramentas, similares, relações) |
| `technique_defense_matrix.csv` | Por técnica: cobertura, regras, formatos convertidos, Defender (tabelas/ASR+GUID), D3FEND, mitigações, data components, RE&CT |
| `group_trace_chain.csv` | Traçagem grupo → ferramenta → técnica → procedimento → defesas (todos os grupos com TTPs) |
| `detections_multiformat.zip` | 866 regras × {sigma, splunk, elastic, eql, esql, opensearch, qradar, stellar, defender} + index.csv |
| `dettect_navigator_react.zip` | DeTT&CT group-administration (todos os grupos ATT&CK), data sources por grupo prioritário, camadas Navigator de cobertura, playbooks RE&CT |
| `IR_tools_catalog.csv` | Catálogo de ferramentas de IR/análise (planilha) |
| `build_scripts.zip` | Pipeline reprodutível (extração, enriquecimento, conversão multi-backend, build) |

## 10. Fontes e limitações
| Fonte | Uso |
|---|---|
| [MITRE ATT&CK – Groups / STIX (mitre/cti)](https://attack.mitre.org/groups/) | Grupos, aliases, técnicas + procedimentos (descrição das relações), software→técnica, campanhas, mitigações (M-codes), data components/log sources (detection strategies → analytics) |
| [APTmap (andreacristaldi) – site + GitHub](https://github.com/andreacristaldi/APTmap) | Coordenadas (validadas por point-in-polygon), países e setores-alvo, motivações, patrocínio, confiança de atribuição, ferramentas com descrição, procedimentos TTP, relações (similar/overlaps/related-to) com linguagem estimativa |
| [ThaiCERT/ETDA – Threat Group Cards (MISP galaxy)](https://apt.etda.or.th/cgi-bin/aptgroups.cgi) | Sinônimos, país (ISO), patrocínio, motivação, setores, vítimas, operações |
| [MISP Galaxy – threat-actor](https://github.com/MISP/misp-galaxy) | Sinônimos, país, setores/vítimas (CFR), relações entre atores (similar/overlaps…) |
| [Google Cloud (Mandiant) – APT groups](https://cloud.google.com/security/resources/insights/apt-groups) | APT1–APT45: atribuição suspeita, setores, visão geral, malware associado, vetores de ataque (texto) |
| [Wikipedia – Advanced persistent threat (lista por país)](https://en.wikipedia.org/wiki/Advanced_persistent_threat) | Lista país→grupos para corroboração e origem |
| [BRANDEFENSE threat-actor-dataset](https://github.com/BRANDEFENSE/threat-actor-dataset) | Aliases, origem, setores, link para perfil com fontes primárias |
| [EternalLiberty](https://github.com/StrangerealIntel/EternalLiberty) | Nomes por fornecedor, tipo, país |
| [Microsoft threat actor naming + MSFT↔CrowdStrike](https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-threat-actor-naming) | Nomes Microsoft (Blizzard/Typhoon/Sandstorm…) e equivalência CrowdStrike |
| [Malpedia (Fraunhofer FKIE)](https://malpedia.caad.fkie.fraunhofer.de/actors) | IDs de ator para links |
| [cyber-research/APTMalware](https://github.com/cyber-research/APTMalware) | Somente contagem de amostras por grupo (metadados) |
| [Planilhas Google fornecidas (APT Groups & Operations; Malware, IR – Tools & Resources)](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit) | Base de nomes/operações/toolset por origem; catálogo de ferramentas IR |
| [SigmaHQ (rules, threat-hunting, emerging-threats)](https://github.com/SigmaHQ/sigma) | 866 regras selecionadas por técnica (até 3; stable/test ≥ medium) + regras de ator |
| [pySigma backends (Splunk, Elasticsearch, OpenSearch, QRadar AQL, Kusto)](https://github.com/SigmaHQ/pySigma) | Splunk 3.0 (pySigma 2.x) · Elasticsearch 2.1 / OpenSearch 2.0 / Kusto 1.0 (pySigma 1.5) · QRadar AQL 0.3 (pySigma 0.11) — ambientes isolados por conflito de dependências |
| [MITRE D3FEND (API)](https://d3fend.mitre.org/) | API offensive-technique/attack/<T>.json para 610 técnicas: contramedida, tática D3FEND e artefatos digitais (ofensivo↔defensivo) |
| [MITRE RE&CT (atc-project/atc-react)](https://github.com/atc-project/atc-react) | 216 response actions (estágio/categoria) mapeadas por facetas da técnica; geração de playbook no formato RP |
| [DeTT&CT (Rabobank CDC)](https://github.com/rabobank-cdc/DeTTECT) | Exportação de YAML group-administration (v1.0), data-source-administration (v1.1) e technique-administration (v1.2) |
| [Microsoft Defender – ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) | GUIDs e ActionTypes de advanced hunting das 19 regras ASR (verificados na página oficial) |
| [Hudson Rock – Cavalier OSINT (infostealers)](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | Atalho de consulta por domínio na aba Priorização (T1078/T1555/T1539) |
| [Radware – Live Threat Map](https://livethreatmap.radware.com/) | Referência visual/contexto (não integrado) |
| [Nuix](https://www.nuix.com/) | Referência (não integrado) |
| [CounterCraft – deception (OT)](https://www.countercraftsec.com/) | Embasamento da tática D3FEND Deceive (decoys PLC/HMI, breadcrumbs, detecção de recon e movimento lateral) |
| [Medium (aardvark) – artigo indicado](https://medium.com/) | Não consumido |
| [world-atlas / D3 / topojson-client](https://github.com/topojson/world-atlas) | Mapa base 110m embutido; centróides calculados do 50m (inclui países pequenos) |

**Limitações:** atribuição contestável e aliases conflitantes entre fontes (fusões frouxas possíveis); vitimologia reflete viés de reporte; mapeamentos Defender/ASR e RE&CT são curados/heurísticos; D3FEND não cobre técnicas pré-ataque e várias recentes; conversões exigem ajuste de campos/índices (Stellar Cyber sem backend oficial; QRadar fallback por payload; Defender XDR sem Script Block/Security/cloud); Hudson Rock, Radware, Nuix e o artigo do Medium (bloqueado) foram apenas referenciados. Nenhuma amostra de malware foi baixada ou executada.