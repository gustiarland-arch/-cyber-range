import { TRAINING } from '@/services/navigation'
import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import AppLayout from '@/layouts/AppLayout.vue'

const routes = [
  {
    path: '/', component: AppLayout, children: [
      { path: '', redirect: { name: 'overview' } },
      { path: 'overview', name: 'overview', component: () => import('@/pages/OverviewPage.vue'), meta: { perm: 'dashboard.view', title: 'Ringkasan' } },
      { path: 'system/health', name: 'system-health', component: () => import('@/pages/SystemHealthPage.vue'), meta: { perm: 'system.health.view', title: 'Kesehatan Sistem' } },
      { path: 'management/audit', name: 'audit', component: () => import('@/pages/AuditLogsPage.vue'), meta: { perm: 'audit.view', title: 'Audit Log' } },
      { path: 'management/settings', name: 'settings', component: () => import('@/pages/SettingsPage.vue'), meta: { perm: 'system.settings.view', title: 'Pengaturan' } },
      { path: 'lab/networks', name: 'networks', component: () => import('@/pages/NetworksPage.vue'), meta: { perm: 'lab.view', title: 'Topologi Jaringan' } },
      { path: 'lab/networks/:id(\\d+)', name: 'network-editor', component: () => import('@/pages/TopologyEditorPage.vue'), meta: { perm: 'lab.view', title: 'Editor Topologi' } },
      { path: 'lab/3d', name: 'network-3d-list', component: () => import('@/pages/NetworksPage.vue'), props: { mode: '3d' }, meta: { perm: 'lab.view', title: 'Jaringan 3D' } },
      { path: 'lab/3d/:id(\\d+)', name: 'network-3d', component: () => import('@/pages/Network3DPage.vue'), meta: { perm: 'lab.view', title: 'Jaringan 3D' } },
      { path: 'lab/labs', name: 'labs', component: () => import('@/pages/LabsPage.vue'), meta: { perm: 'lab.view', title: 'Lab Manager' } },
      { path: 'lab/labs/:id(\\d+)/3d', name: 'lab-3d', component: () => import('@/pages/Network3DPage.vue'), props: { mode: 'lab' }, meta: { perm: 'lab.view', title: 'Lab 3D (hidup)' } },
      { path: 'lab/labs/:id(\\d+)', name: 'lab-detail', component: () => import('@/pages/LabDetailPage.vue'), meta: { perm: 'lab.view', title: 'Lab' } },
      { path: 'lab/workspace/:id(\\d+)?', name: 'network-workspace', component: () => import('@/pages/NetworkWorkspacePage.vue'), meta: { perm: 'lab.view', title: 'Network Intelligence Workspace' } },
      { path: 'lab/vms', name: 'vms', component: () => import('@/pages/VmManagerPage.vue'), meta: { perm: 'lab.view', title: 'Manajer VM' } },
      { path: 'lab/kit', name: 'lab-kit', component: () => import('@/pages/LabKitPage.vue'), meta: { perm: 'lab.kit.download', title: 'Lab Kit' } },
      { path: 'lab/templates', name: 'lab-templates', component: () => import('@/pages/LabTemplatesPage.vue'), meta: { perm: 'lab.view', title: 'Template Lab' } },
      { path: 'command/monitor', name: 'security-monitor', component: () => import('@/pages/SecurityMonitorPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Monitor Keamanan' } },
      { path: 'blue/defense', name: 'defense-center', component: () => import('@/pages/DefenseCenterPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Defense Center' } },
      { path: 'blue/siem', name: 'siem', component: () => import('@/pages/SiemPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'SIEM' } },
      { path: 'blue/ids', name: 'ids', component: () => import('@/pages/SiemPage.vue'), props: { mode: 'ids' }, meta: { perm: 'blueteam.alerts.view', title: 'Deteksi Intrusi' } },
      { path: 'intel/map', name: 'attack-map', component: () => import('@/pages/AttackMapPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Peta Serangan' } },
      { path: 'blue/attack', name: 'attack-coverage', component: () => import('@/pages/AttackCoveragePage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Matriks MITRE ATT&CK' } },
      { path: 'red/purple', name: 'purple-team', component: () => import('@/pages/PurpleTeamPage.vue'), meta: { perm: 'redteam.assessment.view', title: 'Purple Team' } },
      { path: 'blue/soar', name: 'soar', component: () => import('@/pages/SoarPage.vue'), meta: { perm: 'incident.view', title: 'SOAR Playbook' } },
      { path: 'blue/rules', name: 'detection-rules', component: () => import('@/pages/DetectionRulesPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Rule Deteksi' } },
      { path: 'blue/sla', name: 'soc-metrics', component: () => import('@/pages/SocMetricsPage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'SLA & Metrik SOC' } },
      { path: 'blue/incidents', name: 'incident-response', component: () => import('@/pages/IncidentResponsePage.vue'), meta: { perm: 'blueteam.alerts.view', title: 'Respons Insiden' } },
      { path: 'blue/incidents/:id(\\d+)', name: 'incident-detail', component: () => import('@/pages/IncidentDetailPage.vue'), meta: { perm: 'incident.view', title: 'Insiden' } },
      { path: 'red/simulation', name: 'attack-simulation', component: () => import('@/pages/AttackSimulationPage.vue'), meta: { perm: 'redteam.assessment.view', title: 'Simulasi Serangan' } },
      { path: 'red/workspace', name: 'assessment-workspace', component: () => import('@/pages/AttackSimulationPage.vue'), props: { mode: 'workspace' }, meta: { perm: 'redteam.assessment.view', title: 'Workspace Assessment Terotorisasi' } },
      { path: 'red/assessments/:id(\\d+)', name: 'assessment', component: () => import('@/pages/AssessmentDetailPage.vue'), meta: { perm: 'redteam.assessment.view', title: 'Assessment' } },
      { path: 'red/scenarios', name: 'scenarios', component: () => import('@/pages/ScenarioBuilderPage.vue'), meta: { perm: 'redteam.assessment.view', title: 'Penyusun Skenario' } },
      { path: 'red/timeline', name: 'attack-timeline', component: () => import('@/pages/AttackTimelinePage.vue'), meta: { perm: 'redteam.assessment.view', title: 'Timeline Serangan' } },
      { path: 'intel/indicators', name: 'threat-intel', component: () => import('@/pages/ThreatIntelPage.vue'), meta: { perm: 'intel.view', title: 'Threat Intelligence' } },
      { path: 'command/threat-intel', name: 'threat-intel-global', component: () => import('@/pages/GlobalThreatIntelPage.vue'), meta: { perm: 'intel.view', title: 'Threat Intelligence Global' } },
      { path: 'intel/vulnerabilities', name: 'vulnerabilities', component: () => import('@/pages/VulnerabilityPage.vue'), meta: { perm: 'vuln.view', title: 'Manajemen Kerentanan' } },
      { path: 'intel/malware', name: 'malware', component: () => import('@/pages/MalwarePage.vue'), meta: { perm: 'malware.view', title: 'Analisis Malware' } },
      { path: 'intel/malware/:id(\\d+)', name: 'malware-sample', component: () => import('@/pages/SampleDetailPage.vue'), meta: { perm: 'malware.view', title: 'Sampel' } },
      { path: 'intel/forensics', name: 'forensics', component: () => import('@/pages/ForensicsPage.vue'), meta: { perm: 'evidence.view', title: 'Forensik Digital' } },
      { path: 'management/cases', name: 'cases', component: () => import('@/pages/CasesPage.vue'), meta: { perm: 'evidence.view', title: 'Kasus & Evidence' } },
      { path: 'management/cases/:id(\\d+)', name: 'case', component: () => import('@/pages/CaseDetailPage.vue'), meta: { perm: 'evidence.view', title: 'Kasus' } },
      { path: 'management/reports', name: 'reports', component: () => import('@/pages/ReportsPage.vue'), meta: { perm: 'reports.view', title: 'Laporan' } },
      { path: 'training/ctf', name: 'ctf', component: () => import('@/pages/CtfPage.vue'), meta: { perm: TRAINING, title: 'CTF Challenges' } },
      { path: 'training/ctf/:id(\\d+)', name: 'ctf-challenge', component: () => import('@/pages/ChallengeDetailPage.vue'), meta: { perm: TRAINING, title: 'Challenge' } },
      { path: 'training/missions', name: 'missions', component: () => import('@/pages/MissionsPage.vue'), meta: { perm: TRAINING, title: 'Pusat Misi' } },
      { path: 'training/missions/:id(\\d+)', name: 'mission', component: () => import('@/pages/MissionDetailPage.vue'), meta: { perm: TRAINING, title: 'Misi' } },
      { path: 'training/authoring', name: 'training-authoring', component: () => import('@/pages/TrainingAuthoringPage.vue'), meta: { perm: 'training.manage', title: 'Penyusunan Pelatihan' } },
      { path: 'intel/evidence/:id(\\d+)', name: 'evidence', component: () => import('@/pages/EvidenceDetailPage.vue'), meta: { perm: 'evidence.view', title: 'Evidence' } },
      { path: ':pathMatch(.*)*', name: 'not-found', component: () => import('@/pages/NotFoundPage.vue') },
    ],
  },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async () => {
  // Local edition: one operator, no login screen. The session is issued by the backend only to requests from this computer.
  const auth = useAuthStore()
  await auth.init()
  return true
})
router.afterEach((to) => { document.title = to.meta.title ? `${to.meta.title} · CYBER RANGE` : 'CYBER RANGE' })

export default router
