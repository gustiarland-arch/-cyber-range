// Procedural 3D models per device type. Every model stands on the floor (y = 0) and exposes:
//   group.userData.height   top of the model, used for labels and link anchors
//   material.userData.role  'body' (tinted by status/alerts), 'led' (status light), 'detail' (fixed trim)
import * as THREE from 'three'
import { mergeGeometries } from 'three/examples/jsm/utils/BufferGeometryUtils.js'

const box = (w, h, d) => new THREE.BoxGeometry(w, h, d)
const cyl = (rt, rb, h, s = 24) => new THREE.CylinderGeometry(rt, rb, h, s)

function mat(color, role, extra = {}) {
  const m = new THREE.MeshStandardMaterial({ color, metalness: 0.35, roughness: 0.5, emissive: new THREE.Color(color), emissiveIntensity: role === 'body' ? 0.12 : 0.05, ...extra })
  m.userData.role = role
  m.userData.baseColor = new THREE.Color(color)
  m.userData.baseOpacity = m.opacity
  m.userData.baseTransparent = m.transparent
  return m
}
let currentLed = null // one LED material per device model (set by buildDevice), so all its LEDs merge into one draw call
function led(color = 0x22c55e) {
  if (currentLed) return currentLed
  const m = new THREE.MeshBasicMaterial({ color })
  m.userData.role = 'led'
  return m
}
function put(group, geo, material, x, y, z) {
  const m = new THREE.Mesh(geo, material)
  m.position.set(x, y, z)
  group.add(m)
  return m
}

const DARK = 0x1b2638
const TRIM = 0x475569

function serverRack(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), frame = mat(DARK, 'detail'), front = mat(0x0b1220, 'detail', { metalness: 0.6 })
  put(g, box(1.5, 2.8, 1.3), frame, 0, 1.4, 0)
  for (let i = 0; i < 6; i++) {
    put(g, box(1.32, 0.34, 0.06), body, 0, 0.35 + i * 0.42, 0.66)
    put(g, box(0.9, 0.08, 0.02), front, -0.12, 0.35 + i * 0.42, 0.7)
    put(g, new THREE.SphereGeometry(0.045, 8, 8), led(), 0.52, 0.35 + i * 0.42, 0.7)
  }
  g.userData.height = 2.8
  return g
}

function workstation(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), dark = mat(DARK, 'detail'), screen = mat(0x0ea5e9, 'detail', { emissiveIntensity: 0.6 })
  put(g, box(1.8, 0.08, 1.0), mat(TRIM, 'detail'), 0, 0.75, 0)                // desk top
  for (const [x, z] of [[-0.8, -0.4], [0.8, -0.4], [-0.8, 0.4], [0.8, 0.4]]) put(g, box(0.06, 0.75, 0.06), dark, x, 0.375, z)
  put(g, box(1.2, 0.75, 0.06), body, 0, 1.35, -0.25)                           // monitor bezel
  put(g, box(1.08, 0.62, 0.02), screen, 0, 1.36, -0.21)                        // screen
  put(g, box(0.08, 0.25, 0.08), dark, 0, 0.92, -0.28)                          // stand
  put(g, box(0.7, 0.03, 0.25), dark, 0, 0.81, 0.15)                            // keyboard
  put(g, box(0.35, 0.7, 0.75), body, 0.65, 0.35, 0.05)                         // tower under desk
  put(g, new THREE.SphereGeometry(0.04, 8, 8), led(), 0.65, 0.62, 0.44)
  g.userData.height = 1.75
  return g
}

function firewall(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), mortar = mat(0x3f1d0b, 'detail')
  put(g, box(2.4, 1.6, 0.5), mortar, 0, 0.8, 0)
  for (let row = 0; row < 4; row++) {
    const off = row % 2 ? 0.3 : 0
    for (let col = -2; col <= 2; col++) {
      const x = col * 0.6 + off
      if (Math.abs(x) > 1.0) continue
      put(g, box(0.54, 0.34, 0.56), body, x, 0.2 + row * 0.4, 0)
    }
  }
  put(g, box(0.5, 0.12, 0.1), mat(DARK, 'detail'), 0, 1.72, 0.2)
  put(g, new THREE.SphereGeometry(0.06, 8, 8), led(), 0.15, 1.72, 0.27)
  g.userData.height = 1.8
  return g
}

function router(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), dark = mat(DARK, 'detail')
  put(g, cyl(1.0, 1.05, 0.5, 32), body, 0, 0.5, 0)
  put(g, cyl(1.06, 1.06, 0.06, 32), dark, 0, 0.26, 0)
  for (const a of [-0.6, 0, 0.6]) {
    const ant = put(g, cyl(0.04, 0.05, 1.1, 8), dark, Math.sin(a) * 0.75, 1.2, -Math.cos(a) * 0.75)
    ant.rotation.z = a * 0.4
  }
  for (let i = 0; i < 4; i++) put(g, new THREE.SphereGeometry(0.05, 8, 8), led(), -0.45 + i * 0.3, 0.6, 0.98)
  g.userData.height = 1.8
  return g
}

function switchBox(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), port = mat(0x0b1220, 'detail')
  put(g, box(2.4, 0.4, 1.1), body, 0, 0.6, 0)
  put(g, box(2.5, 0.5, 0.06), mat(DARK, 'detail'), 0, 0.55, 0.56)
  for (let i = 0; i < 12; i++) {
    put(g, box(0.13, 0.11, 0.04), port, -1.0 + i * 0.18, 0.6, 0.58)
    if (i % 3 === 0) put(g, new THREE.SphereGeometry(0.025, 6, 6), led(), -1.0 + i * 0.18, 0.72, 0.59)
  }
  put(g, box(2.2, 0.4, 0.9), mat(DARK, 'detail'), 0, 0.2, 0)                     // rack shelf
  g.userData.height = 0.85
  return g
}

function database(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), band = mat(DARK, 'detail')
  for (let i = 0; i < 3; i++) {
    put(g, cyl(0.85, 0.85, 0.55, 32), body, 0, 0.3 + i * 0.62, 0)
    put(g, cyl(0.87, 0.87, 0.06, 32), band, 0, 0.6 + i * 0.62, 0)
  }
  put(g, new THREE.SphereGeometry(0.06, 8, 8), led(), 0, 1.6, 0.86)
  g.userData.height = 2.0
  return g
}

function internet(color) {
  const g = new THREE.Group()
  const m = mat(color, 'body', { wireframe: true, transparent: true, opacity: 0.8 })
  put(g, new THREE.IcosahedronGeometry(1.6, 2), m, 0, 5, 0)
  put(g, new THREE.SphereGeometry(1.45, 24, 16), mat(0x0f2742, 'detail', { transparent: true, opacity: 0.35 }), 0, 5, 0)
  put(g, cyl(0.03, 0.03, 3.4, 6), mat(TRIM, 'detail'), 0, 1.7, 0)
  g.userData.height = 6.6
  return g
}

function vm(color) {
  const g = new THREE.Group()
  const shell = mat(color, 'body', { transparent: true, opacity: 0.35 })
  put(g, box(1.5, 1.5, 1.5), shell, 0, 0.85, 0)
  put(g, box(0.8, 0.8, 0.8), mat(color, 'detail', { emissiveIntensity: 0.4 }), 0, 0.85, 0)
  const edges = new THREE.LineSegments(new THREE.EdgesGeometry(box(1.5, 1.5, 1.5)), new THREE.LineBasicMaterial({ color }))
  edges.position.set(0, 0.85, 0)
  g.add(edges)
  put(g, new THREE.SphereGeometry(0.05, 8, 8), led(), 0.6, 1.5, 0.76)
  g.userData.height = 1.7
  return g
}

function container(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body'), rib = mat(DARK, 'detail')
  put(g, box(2.0, 0.9, 0.9), body, 0, 0.45, 0)
  for (let i = 0; i < 7; i++) put(g, box(0.05, 0.86, 0.94), rib, -0.9 + i * 0.3, 0.45, 0)
  put(g, new THREE.SphereGeometry(0.05, 8, 8), led(), 0.85, 0.8, 0.47)
  g.userData.height = 1.0
  return g
}

function sensor(color) {
  const g = new THREE.Group()
  const body = mat(color, 'body')
  put(g, cyl(0.08, 0.1, 1.2, 8), mat(TRIM, 'detail'), 0, 0.6, 0)
  put(g, new THREE.SphereGeometry(0.55, 24, 16, 0, Math.PI * 2, 0, Math.PI / 2), body, 0, 1.2, 0)
  const ring = put(g, new THREE.TorusGeometry(0.7, 0.04, 8, 32), mat(color, 'detail', { emissiveIntensity: 0.6 }), 0, 1.25, 0)
  ring.rotation.x = Math.PI / 2
  ring.userData.spin = true
  put(g, new THREE.SphereGeometry(0.05, 8, 8), led(), 0, 1.78, 0)
  g.userData.height = 1.8
  return g
}

function generic(color) {
  const g = new THREE.Group()
  put(g, box(1, 1, 1), mat(color, 'body'), 0, 0.5, 0)
  put(g, new THREE.SphereGeometry(0.05, 8, 8), led(), 0.4, 1.0, 0.5)
  g.userData.height = 1.1
  return g
}

const BUILDERS = { server: serverRack, workstation, firewall, router, switch: switchBox, database, internet, vm, container, sensor }

/** Build the model of a device type in the given hex color. */
export function buildDevice(type, color) {
  currentLed = new THREE.MeshBasicMaterial({ color: 0x22c55e })
  currentLed.userData.role = 'led'
  const g = (BUILDERS[type] || generic)(color)
  currentLed = null
  mergeByMaterial(g)
  g.traverse((o) => { if (o.isMesh) o.castShadow = true })
  return g
}

/**
 * Merge the static meshes of one model that share a material into a single mesh. A server rack goes from ~20 draw
 * calls to 4; the look is identical. Meshes that animate on their own (userData.spin) and line objects stay separate.
 */
function mergeByMaterial(group) {
  group.updateMatrixWorld(true)
  const buckets = new Map()
  for (const child of [...group.children]) {
    if (!child.isMesh || child.userData.spin) continue
    const geo = child.geometry.clone().applyMatrix4(child.matrix)
    for (const k of Object.keys(geo.attributes)) if (!['position', 'normal', 'uv'].includes(k)) geo.deleteAttribute(k)
    buckets.set(child.material, [...(buckets.get(child.material) || []), geo])
    group.remove(child)
    child.geometry.dispose()
  }
  for (const [material, geos] of buckets) {
    // mergeGeometries needs all-indexed or all-non-indexed input
    const same = geos.every((x) => x.index) ? geos : geos.map((x) => (x.index ? x.toNonIndexed() : x))
    const merged = mergeGeometries(same, false)
    for (const x of geos) x.dispose()
    if (merged) group.add(new THREE.Mesh(merged, material))
  }
}

/** Materials of a model grouped by role, so the scene can tint them for status and alerts. */
export function materialsOf(group) {
  const out = { body: [], led: [], detail: [] }
  group.traverse((o) => {
    const m = o.material
    if (m?.userData?.role && out[m.userData.role] && !out[m.userData.role].includes(m)) out[m.userData.role].push(m)
  })
  return out
}
