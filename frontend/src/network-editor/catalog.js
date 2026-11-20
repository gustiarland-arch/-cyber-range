import { BrickWall, Box, Container, Database, Globe, Monitor, Network, Radar, Router, Server } from 'lucide-vue-next'

// Shared by the 2D editor and the 3D view so both render the same device semantics.
export const DEVICES = {
  server: { label: 'Server', icon: Server, color: '#22d3ee' },
  workstation: { label: 'Workstation', icon: Monitor, color: '#60a5fa' },
  router: { label: 'Router', icon: Router, color: '#34d399' },
  switch: { label: 'Switch', icon: Network, color: '#a3e635' },
  firewall: { label: 'Firewall', icon: BrickWall, color: '#f97316' },
  database: { label: 'Database', icon: Database, color: '#c084fc' },
  internet: { label: 'Internet', icon: Globe, color: '#94a3b8' },
  vm: { label: 'Virtual machine', icon: Box, color: '#38bdf8' },
  container: { label: 'Container', icon: Container, color: '#2dd4bf' },
  sensor: { label: 'Sensor', icon: Radar, color: '#facc15' },
}

export const ZONE_COLORS = { internet: '#64748b', dmz: '#f59e0b', internal: '#3b82f6', management: '#10b981', lab: '#ec4899', restricted: '#a855f7' }

export function newKey(prefix, taken) {
  for (;;) {
    const k = `${prefix}-${Math.random().toString(36).slice(2, 8)}`
    if (!taken.has(k)) return k
  }
}

/** Deep clone a plain JSON document. */
export const clone = (o) => JSON.parse(JSON.stringify(o))

/** Determine which zone contains a point (topmost = last declared). */
export function zoneAt(doc, x, y) {
  for (let i = doc.zones.length - 1; i >= 0; i--) {
    const z = doc.zones[i]
    if (x >= z.position.x && x <= z.position.x + z.size.w && y >= z.position.y && y <= z.position.y + z.size.h) return z.key
  }
  return null
}

export function primaryIp(node) {
  return node.interfaces?.find((i) => i.ip)?.ip || ''
}
