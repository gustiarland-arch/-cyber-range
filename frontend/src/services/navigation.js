// Single source of truth for the sidebar, command palette and route permissions.
import {
  SquareTerminal, Activity, BarChart3, Boxes, Bug, ClipboardList, Cpu, Crosshair, FileSearch, FileText, Flag, Gauge, Globe, HeartPulse, LayoutTemplate, ListChecks, Network, Radar, ScrollText, Settings, Shield, ShieldAlert, ShieldCheck, Siren, Swords, Blend, Grid3x3, Earth, Zap, Target, Workflow, Box, Fingerprint, Library, Map, Server, Timer, PackageOpen,
} from 'lucide-vue-next'

export const TRAINING = 'training.participate|training.manage'

export const NAV = [
  { section: 'Command Center', items: [
    { label: 'Dashboard Overview', to: 'overview', icon: Gauge, perm: 'dashboard.view' },
    { label: 'Monitor Keamanan Real-time', to: 'security-monitor', icon: Activity, perm: 'blueteam.alerts.view' },
    { label: 'Threat Intelligence Global', to: 'threat-intel-global', icon: Globe, perm: 'intel.view' },
    { label: 'Peta Serangan', to: 'attack-map', icon: Earth, perm: 'blueteam.alerts.view' },
    { label: 'Kesehatan Sistem', to: 'system-health', icon: HeartPulse, perm: 'system.health.view' },
  ]},
  { section: 'Red Team Operations', tone: 'red', items: [
    { label: 'Simulasi Serangan', to: 'attack-simulation', icon: Swords, perm: 'redteam.assessment.view' },
    { label: 'Penyusun Skenario', to: 'scenarios', icon: Workflow, perm: 'redteam.assessment.view' },
    { label: 'Timeline Serangan', to: 'attack-timeline', icon: Map, perm: 'redteam.assessment.view' },
    { label: 'Purple Team: Diserang vs Terdeteksi', to: 'purple-team', icon: Blend, perm: 'redteam.assessment.view' },
    { label: 'Workspace Assessment Terotorisasi', to: 'assessment-workspace', icon: Target, perm: 'redteam.assessment.view' },
  ]},
  { section: 'Blue Team Operations', tone: 'blue', items: [
    { label: 'Defense Center', to: 'defense-center', icon: ShieldCheck, perm: 'blueteam.alerts.view' },
    { label: 'SIEM & Analisis Log', to: 'siem', icon: FileSearch, perm: 'blueteam.alerts.view' },
    { label: 'Deteksi Intrusi', to: 'ids', icon: Radar, perm: 'blueteam.alerts.view' },
    { label: 'Respons Insiden', to: 'incident-response', icon: Siren, perm: 'blueteam.alerts.view' },
    { label: 'SOAR Playbook', to: 'soar', icon: Zap, perm: 'incident.view' },
    { label: 'SLA & Metrik SOC', to: 'soc-metrics', icon: Timer, perm: 'blueteam.alerts.view' },
    { label: 'Rule Deteksi', to: 'detection-rules', icon: ListChecks, perm: 'blueteam.alerts.view' },
    { label: 'Matriks MITRE ATT&CK', to: 'attack-coverage', icon: Grid3x3, perm: 'blueteam.alerts.view' },
  ]},
  { section: 'Cyber Range Lab', items: [
    { label: 'Lab Manager', to: 'labs', icon: Server, perm: 'lab.view' },
    { label: 'Network Intelligence Workspace', to: 'network-workspace', icon: SquareTerminal, perm: 'lab.view' },
    { label: 'Visualisasi Jaringan 3D', to: 'network-3d-list', icon: Boxes, perm: 'lab.view' },
    { label: 'Editor Topologi Jaringan', to: 'networks', icon: Network, perm: 'lab.view' },
    { label: 'Manajer Virtual Machine', to: 'vms', icon: Cpu, perm: 'lab.view' },
    { label: 'Template Lab', to: 'lab-templates', icon: LayoutTemplate, perm: 'lab.view' },
    { label: 'Lab Kit (unduh)', to: 'lab-kit', icon: PackageOpen, perm: 'lab.kit.download', hint: 'Jalankan lab di komputer atau VM lain' },
    { label: 'Manajemen Skenario', to: 'scenarios', icon: Box, perm: 'redteam.assessment.view' },
  ]},
  { section: 'Security Intelligence', items: [
    { label: 'Threat Intelligence', to: 'threat-intel', icon: Crosshair, perm: 'intel.view' },
    { label: 'Manajemen Kerentanan', to: 'vulnerabilities', icon: ShieldAlert, perm: 'vuln.view' },
    { label: 'Analisis Malware', to: 'malware', icon: Bug, perm: 'malware.view' },
    { label: 'Forensik Digital', to: 'forensics', icon: Fingerprint, perm: 'evidence.view' },
  ]},
  { section: 'Latihan: CTF & Misi', items: [
    { label: 'CTF Challenges', to: 'ctf', icon: Flag, perm: TRAINING },
    { label: 'Pusat Misi', to: 'missions', icon: Library, perm: TRAINING },
  ]},
  { section: 'Manajemen', items: [
    { label: 'Laporan', to: 'reports', icon: BarChart3, perm: 'reports.view' },
    { label: 'Kasus & Evidence', to: 'cases', icon: ClipboardList, perm: 'evidence.view' },
    { label: 'Audit Log', to: 'audit', icon: ScrollText, perm: 'audit.view' },
    { label: 'Pengaturan Sistem', to: 'settings', icon: Settings, perm: 'system.settings.view' },
  ]},
]

export const BRAND_ICON = Shield
export const REPORT_ICON = FileText
