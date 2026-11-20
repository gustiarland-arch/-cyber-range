// Three.js renderer for a CYBER RANGE topology document (the same model the 2D editor saves).
// Two modes share this scene:
//   * design view  build(doc) only: the saved topology, read-only (optional decorative link animation);
//   * live lab     build(doc) + applyLive(frame): node status from the running lab, real sensor traffic,
//                  red team steps and alerts. Nothing in the live layers is decorative: every line, particle
//                  and blink is driven by the frame computed from /labs/{id}/live (see liveModel.js).
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import { CSS2DObject, CSS2DRenderer } from 'three/examples/jsm/renderers/CSS2DRenderer.js'
import { mergeGeometries } from 'three/examples/jsm/utils/BufferGeometryUtils.js'
import { DEVICES } from '@/network-editor/catalog'
import { buildDevice, materialsOf } from './devices.js'
import { SEV_COLOR, STATE_COLOR, STATE_LABEL, flowParticles, flowRadius } from './liveModel.js'

const S = 1 / 20 // 2D px -> world units
const WALL_H = 3.2
const DEVICE_SCALE = 1.6
const MAX_PARTICLES = 700
const MAX_ATTACK_PARTICLES = 300
const MERGE_FLOWS_ABOVE = 60   // beyond this many links, tubes of one colour are merged into one draw call
const SHADOWS_UP_TO_NODES = 40 // shadows double the draw calls; large labs render without them
const COMPACT_LABELS_ABOVE = 30 // larger labs: name-only labels, details on selection/alert, distant labels hidden
const C = (hex) => new THREE.Color(hex)

export class NetworkScene {
  constructor(container, { onSelect, onFocus } = {}) {
    this.container = container
    this.onSelect = onSelect || (() => {})
    this.onFocus = onFocus || (() => {})
    this.nodes = new Map() // key -> { group, mats, label, ring, halo, pos, top, data, state, ghost }
    this.links = []        // topology links { key, a, b, line, curve }
    this.decor = []        // decorative particles (design view only)
    this.flowObjs = []     // live traffic tubes + particles
    this.attackObjs = []   // live red team paths + particles
    this.flow = false
    this.labels = true
    this.selected = null
    this.live = false
    this.blinking = new Map()
    this.tween = null

    const { clientWidth: w, clientHeight: h } = container
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    this.renderer.setSize(w, h)
    this.renderer.shadowMap.enabled = true
    container.appendChild(this.renderer.domElement)
    this.labelRenderer = new CSS2DRenderer()
    this.labelRenderer.setSize(w, h)
    Object.assign(this.labelRenderer.domElement.style, { position: 'absolute', inset: '0', pointerEvents: 'none' })
    container.appendChild(this.labelRenderer.domElement)

    this.scene = new THREE.Scene()
    this.scene.fog = new THREE.Fog(0x050a14, 90, 240)
    this.camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 1000)
    this.controls = new OrbitControls(this.camera, this.renderer.domElement)
    this.controls.enableDamping = true
    this.controls.maxPolarAngle = Math.PI * 0.49
    this.controls.addEventListener('start', () => { this.tween = null })

    this.scene.add(new THREE.HemisphereLight(0x9bdcff, 0x050a14, 1.0))
    const dir = new THREE.DirectionalLight(0xffffff, 1.5)
    dir.position.set(30, 60, 20)
    dir.castShadow = true
    dir.shadow.mapSize.set(2048, 2048)
    Object.assign(dir.shadow.camera, { left: -80, right: 80, top: 80, bottom: -80, far: 200 })
    this.scene.add(dir)
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(600, 600), new THREE.ShadowMaterial({ opacity: 0.35 }))
    floor.rotation.x = -Math.PI / 2
    floor.receiveShadow = true
    this.scene.add(floor)
    const grid = new THREE.GridHelper(400, 160, 0x22395a, 0x0f1d31)
    grid.material.transparent = true
    grid.material.opacity = 0.45
    this.scene.add(grid)
    this.world = new THREE.Group()
    this.scene.add(this.world)
    this.liveLayer = new THREE.Group()
    this.scene.add(this.liveLayer)
    // particle pools: one instanced draw call each, however many particles are moving
    this.flowPool = this.makePool(new THREE.SphereGeometry(1, 10, 10), MAX_PARTICLES)
    this.attackPool = this.makePool(new THREE.ConeGeometry(0.18, 0.5, 8).rotateX(Math.PI / 2), MAX_ATTACK_PARTICLES)
    this.flowParts = []
    this.attackParts = []
    this.tmpM = new THREE.Matrix4()
    this.tmpQ = new THREE.Quaternion()
    this.tmpV = new THREE.Vector3()
    this.tmpS = new THREE.Vector3()

    this.raycaster = new THREE.Raycaster()
    this.pointer = new THREE.Vector2()
    this._onClick = (e) => this.pick(e, 'click')
    this._onDbl = (e) => this.pick(e, 'dbl')
    this._onMove = (e) => this.pick(e, 'move')
    this.renderer.domElement.addEventListener('click', this._onClick)
    this.renderer.domElement.addEventListener('dblclick', this._onDbl)
    this.renderer.domElement.addEventListener('pointermove', this._onMove)
    this.ro = new ResizeObserver(() => this.resize())
    this.ro.observe(container)
    this.clock = new THREE.Clock()
    this.t = 0
    this.running = true
    this.loop()
  }

  makePool(geometry, capacity) {
    const mesh = new THREE.InstancedMesh(geometry, new THREE.MeshBasicMaterial({ color: 0xffffff }), capacity)
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage)
    mesh.count = 0
    mesh.frustumCulled = false
    mesh.material.userData.shared = true
    this.scene.add(mesh)
    return mesh
  }

  // ------------------------------------------------------------------ topology
  build(doc, issues = []) {
    this.clearWorld()
    this.renderer.shadowMap.enabled = doc.nodes.length <= SHADOWS_UP_TO_NODES
    this.compact = doc.nodes.length > COMPACT_LABELS_ABOVE
    const errNodes = new Set(issues.filter((i) => i.severity === 'error' && i.ref?.node).map((i) => i.ref.node))
    const xs = doc.nodes.map((n) => n.position.x + 75), ys = doc.nodes.map((n) => n.position.y + 24)
    this.center = doc.nodes.length ? { x: (Math.min(...xs) + Math.max(...xs)) / 2, y: (Math.min(...ys) + Math.max(...ys)) / 2 } : { x: 0, y: 0 }
    this.W = (x, y) => [(x - this.center.x) * S, (y - this.center.y) * S]

    for (const z of doc.zones) this.addRoom(z)
    for (const n of doc.nodes) this.addNode(n, { error: errNodes.has(n.key) })
    for (const l of doc.links) {
      const a = this.nodes.get(l.source), b = this.nodes.get(l.target)
      if (!a || !b) continue
      const curve = this.arc(a.top, b.top, 0.12)
      const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(32)),
        new THREE.LineBasicMaterial({ color: 0x3a8bb5, transparent: true, opacity: 0.7 }))
      this.world.add(line)
      this.links.push({ key: l.key, a: l.source, b: l.target, line, curve, data: l })
    }
    this.setFlow(this.flow)
    this.setLabels(this.labels)
    this.resetView()
  }

  /** A zone drawn as a room: floor, translucent walls with a doorway gap, and a name plate. */
  addRoom(z) {
    const [cx, cz] = this.W(z.position.x + z.size.w / 2, z.position.y + z.size.h / 2)
    const w = z.size.w * S, d = z.size.h * S
    const color = C(z.color || '#3b82f6')
    const room = new THREE.Group()
    room.position.set(cx, 0, cz)
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(w, d), new THREE.MeshStandardMaterial({ color, transparent: true, opacity: 0.12, roughness: 0.9, depthWrite: false }))
    floor.rotation.x = -Math.PI / 2
    floor.position.y = 0.02
    floor.receiveShadow = true
    room.add(floor)
    const wallMat = new THREE.MeshStandardMaterial({ color, transparent: true, opacity: 0.1, side: THREE.DoubleSide, depthWrite: false })
    const edgeMat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.75 })
    const door = Math.min(3, w * 0.3)
    const walls = [
      [w, 0, -d / 2, 0], [d, -w / 2, 0, Math.PI / 2], [d, w / 2, 0, Math.PI / 2],
      [(w - door) / 2, -(w + door) / 4, d / 2, 0], [(w - door) / 2, (w + door) / 4, d / 2, 0], // front wall with a doorway
    ]
    for (const [len, x, zz, rot] of walls) {
      if (len <= 0.05) continue
      const geo = new THREE.PlaneGeometry(len, WALL_H)
      const wall = new THREE.Mesh(geo, wallMat)
      wall.position.set(x, WALL_H / 2, zz)
      wall.rotation.y = rot
      const edge = new THREE.LineSegments(new THREE.EdgesGeometry(geo), edgeMat)
      edge.position.copy(wall.position)
      edge.rotation.y = rot
      room.add(wall, edge)
    }
    const tag = this.makeLabel(`<span style="color:${escape(z.color || '#3b82f6')}">${escape(z.name)}</span>`, 'zone')
    tag.position.set(-w / 2 + Math.min(3, w / 3), WALL_H + 0.4, -d / 2)
    room.add(tag)
    this.world.add(room)
  }

  addNode(n, { error = false, ghost = false, position } = {}) {
    const dev = DEVICES[n.type] || DEVICES.server
    const group = ghost ? this.ghostModel() : buildDevice(n.type, dev.color)
    if (!ghost) {
      group.scale.setScalar(DEVICE_SCALE)
      group.userData.height = (group.userData.height || 1.5) * DEVICE_SCALE
    }
    let x, z
    if (position) [x, z] = position
    else [x, z] = this.W(n.position.x + 75, n.position.y + 24)
    group.position.set(x, 0, z)
    group.traverse((o) => { o.userData.key = n.key })
    const height = group.userData.height || 1.5
    const ring = new THREE.Mesh(new THREE.RingGeometry(2.1, 2.45, 48), new THREE.MeshBasicMaterial({
      color: error ? 0xf43f5e : dev.color, transparent: true, opacity: error ? 0.9 : 0.35, side: THREE.DoubleSide, depthWrite: false }))
    ring.rotation.x = -Math.PI / 2
    ring.position.set(x, 0.05, z)
    // alert beacon: an open, see-through column of light around the device (never hides the model itself)
    const halo = new THREE.Mesh(new THREE.CylinderGeometry(2.2, 2.2, height + 3, 40, 1, true),
      new THREE.MeshBasicMaterial({ color: 0xf43f5e, transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false }))
    halo.position.set(x, (height + 3) / 2, z)
    halo.visible = false
    const ip = n.interfaces?.find((i) => i.ip)?.ip
    const label = this.makeLabel(this.labelHtml(n.label, ip ? [ip] : [], null), 'node')
    label.position.set(x, height + 0.9, z)
    this.world.add(group, ring, halo, label)
    const top = new THREE.Vector3(x, height * 0.8, z)
    this.nodes.set(n.key, { key: n.key, group, mats: materialsOf(group), label, ring, halo, pos: new THREE.Vector3(x, height / 2, z), top, height,
      data: n, state: null, ghost, baseRing: error ? 0xf43f5e : C(dev.color).getHex(), baseRingOpacity: error ? 0.9 : 0.35 })
  }

  ghostModel() {
    const g = new THREE.Group()
    const m = new THREE.MeshStandardMaterial({ color: 0x94a3b8, transparent: true, opacity: 0.5, emissive: 0x334155 })
    m.userData.role = 'body'
    m.userData.baseColor = C(0x94a3b8)
    m.userData.baseOpacity = 0.5
    m.userData.baseTransparent = true
    const s = new THREE.Mesh(new THREE.OctahedronGeometry(0.7), m)
    s.position.y = 1.2
    g.add(s)
    g.userData.height = 2
    return g
  }

  labelHtml(name, ips, state, extra = '') {
    const st = state ? `<span class="st" style="color:${STATE_COLOR[state]}">● ${escape(STATE_LABEL[state] || state)}</span><br>` : ''
    return `<b>${escape(name)}</b><br>${st}${ips.map((i) => `<span class="ip">${escape(i)}</span>`).join('<br>')}${extra}`
  }

  arc(a, b, lift = 0.12, extra = 0) {
    const mid = a.clone().lerp(b, 0.5)
    mid.y += Math.max(1.5, a.distanceTo(b) * lift) + extra
    return new THREE.QuadraticBezierCurve3(a.clone(), mid, b.clone())
  }

  makeLabel(html, cls) {
    const el = document.createElement('div')
    el.className = `cr3d-label cr3d-${cls}`
    el.innerHTML = html
    return new CSS2DObject(el)
  }

  disposeTree(root) {
    root.traverse((o) => { o.geometry?.dispose?.(); if (o.material && !o.material.userData?.shared) o.material.dispose?.(); if (o.isCSS2DObject) o.element.remove() })
  }

  clearWorld() {
    this.clearLive()
    for (const p of this.decor) this.world.remove(p.mesh)
    this.decor = []
    this.disposeTree(this.world)
    this.world.clear()
    this.nodes.clear()
    this.links = []
    this.selected = null
  }

  clearLive() {
    for (const o of [...this.flowObjs, ...this.attackObjs]) if (o.mesh) this.liveLayer.remove(o.mesh)
    this.disposeTree(this.liveLayer)
    this.liveLayer.clear()
    this.flowObjs = []
    this.attackObjs = []
    this.flowParts = []
    this.attackParts = []
    this.flowPool.count = 0
    this.attackPool.count = 0
  }

  // ------------------------------------------------------------------ camera
  bounds() {
    const pts = [...this.nodes.values()].map((n) => n.pos)
    const box = new THREE.Box3().setFromPoints(pts.length ? pts : [new THREE.Vector3()])
    return { size: Math.max(20, box.getSize(new THREE.Vector3()).length()), c: box.getCenter(new THREE.Vector3()) }
  }

  resetView(top = false) {
    const { size, c } = this.bounds()
    const cam = top ? new THREE.Vector3(c.x, size * 1.2, c.z + 0.01) : new THREE.Vector3(c.x + size * 0.45, size * 0.6, c.z + size * 0.75)
    this.flyTo(cam, c, this.camera.position.lengthSq() === 0 ? 0 : 0.7)
  }

  /** Smoothly move the camera to look at one node from a close, slightly raised angle. */
  focus(key) {
    const n = this.nodes.get(key)
    if (!n) return false
    const dir = this.camera.position.clone().sub(this.controls.target).setY(0)
    if (dir.lengthSq() < 0.01) dir.set(0.6, 0, 1)
    dir.normalize().multiplyScalar(12 + n.height * 2.2)
    this.flyTo(n.pos.clone().add(dir).setY(n.height * 1.6 + 5), n.pos.clone(), 0.8)
    this.onFocus(key)
    return true
  }

  flyTo(camPos, target, seconds) {
    if (!seconds) {
      this.camera.position.copy(camPos)
      this.controls.target.copy(target)
      this.controls.update()
      return
    }
    this.tween = { t: 0, dur: seconds, fromCam: this.camera.position.clone(), toCam: camPos, fromTgt: this.controls.target.clone(), toTgt: target }
  }

  // ------------------------------------------------------------------ design-view helpers
  setFlow(on) {
    this.flow = on
    for (const p of this.decor) { this.world.remove(p.mesh); p.mesh.geometry.dispose(); p.mesh.material.dispose() }
    this.decor = []
    if (!on || this.live) return
    for (const l of this.links) {
      for (let i = 0; i < 2; i++) {
        const mesh = new THREE.Mesh(new THREE.SphereGeometry(0.18, 10, 10), new THREE.MeshBasicMaterial({ color: 0x67e8f9 }))
        this.world.add(mesh)
        this.decor.push({ mesh, curve: l.curve, t: Math.random(), speed: 0.15 + Math.random() * 0.2, dir: i ? -1 : 1 })
      }
    }
  }

  setLabels(on) {
    this.labels = on
    for (const root of [this.world, this.liveLayer]) root.traverse((o) => { if (o.isCSS2DObject) o.visible = on })
  }

  select(key) {
    this.selected = key
    const neighbors = new Set([key])
    for (const l of this.links) {
      const hit = key && (l.a === key || l.b === key)
      if (hit) { neighbors.add(l.a); neighbors.add(l.b) }
      l.line.material.color.set(hit ? 0x22d3ee : 0x3a8bb5)
      l.line.material.opacity = !key || hit ? (hit ? 1 : 0.7) : 0.12
    }
    for (const f of this.flowObjs) if (key && f.src && (f.src === key || f.dst === key)) { neighbors.add(f.src); neighbors.add(f.dst) }
    for (const [k, n] of this.nodes) {
      const dim = key && !neighbors.has(k)
      n.dim = dim
      if (this.compact && n.htmlFull) n.label.element.innerHTML = k === key ? n.htmlFull : n.htmlCompact
      n.label.element.style.opacity = dim ? '0.25' : '1'
      this.paintNode(n)
    }
    for (const f of this.flowObjs) if (f.kind === 'tube') f.mesh.material.opacity = key && f.src !== key && f.dst !== key ? 0.08 : f.baseOpacity
    for (const f of this.flowObjs) if (f.kind === 'merged') f.mesh.material.opacity = key ? 0.08 : f.baseOpacity
    this.drawFlowHighlight(key)
  }

  // ------------------------------------------------------------------ live layers
  /**
   * Apply one live frame:
   *   nodes     Map key -> { state, ips[], planned, alerts }
   *   external  [{ key, ip, events }]
   *   flows     flowsAt() output
   *   blinking  Map key -> severity of alerts active at the cursor
   *   seen      Map key -> alerts in the window (static badge)
   *   attack    { attacker, steps: stepsAt() output } | null
   */
  applyLive(frame) {
    this.lastFrame = frame
    this.live = true
    if (this.decor.length) this.setFlow(false)
    this.syncExternal(frame.external || [])
    for (const [k, n] of this.nodes) {
      const st = frame.nodes.get(k)
      if (n.ghost) {
        n.state = 'running'
        n.label.element.innerHTML = this.labelHtml(n.data.label, [], null, '<br><span class="ext">luar topologi</span>')
        continue
      }
      n.state = st?.state || 'absent'
      const ips = st?.ips || []
      const seen = frame.seen.get(k)?.length || 0
      const extra = (st?.planned && ips.length ? '<br><span class="planned">IP rencana</span>' : '') +
        (seen ? `<br><span class="alert">⚠ ${seen} alert</span>` : '') + (frame.attack?.attacker === k ? '<br><span class="attacker">penyerang</span>' : '')
      n.htmlFull = this.labelHtml(n.data.label, ips, n.state, extra)
      n.htmlCompact = `<b>${escape(n.data.label)}</b> <span class="st" style="color:${STATE_COLOR[n.state]}">●</span>${seen ? ` <span class="alert">⚠${seen}</span>` : ''}`
      n.label.element.innerHTML = this.compact && k !== this.selected ? n.htmlCompact : n.htmlFull
      n.label.element.dataset.state = n.state
    }
    this.blinking = frame.blinking
    for (const n of this.nodes.values()) this.paintNode(n)
    this.drawFlows(frame.flows)
    this.drawAttack(frame.attack)
    if (this.selected) this.select(this.selected)
    this.setLabels(this.labels)
  }

  /** Ghost nodes for traffic endpoints outside the topology, placed on a circle around the lab. */
  syncExternal(list) {
    const want = new Set(list.map((e) => e.key))
    for (const [k, n] of [...this.nodes]) {
      if (n.ghost && !want.has(k)) {
        for (const o of [n.group, n.ring, n.halo, n.label]) { this.world.remove(o); this.disposeTree(o) }
        this.nodes.delete(k)
      }
    }
    const { size, c } = this.bounds()
    list.forEach((e, i) => {
      if (this.nodes.has(e.key)) return
      const a = (i / Math.max(1, list.length)) * Math.PI * 2
      const r = size * 0.55 + 6
      this.addNode({ key: e.key, label: e.ip, type: 'internet', interfaces: [] }, { ghost: true, position: [c.x + Math.cos(a) * r, c.z + Math.sin(a) * r] })
    })
  }

  /** Tint a node's materials and status ring for its current state, alert blink and selection. */
  paintNode(n) {
    const state = this.live ? n.state : null
    const color = state ? C(STATE_COLOR[state]) : null
    for (const m of n.mats.led) m.color.copy(color || C(0x22c55e))
    const off = state === 'stopped' || state === 'absent'
    for (const m of n.mats.body) {
      const base = m.userData.baseColor
      m.color.copy(off ? base.clone().lerp(C(0x1e293b), 0.75) : base)
      m.emissive.copy(state === 'error' ? C(0xf43f5e) : off ? C(0x0b1220) : base)
      m.emissiveIntensity = n.key === this.selected ? 0.7 : state === 'error' ? 0.5 : 0.12
      const baseOpacity = m.userData.baseOpacity ?? 1
      m.opacity = n.dim ? 0.18 : off ? Math.min(baseOpacity, 0.55) : baseOpacity
      m.transparent = m.opacity < 1 || !!m.userData.baseTransparent
      m.needsUpdate = true
    }
    if (state) {
      n.ring.material.color.copy(color)
      n.ring.material.opacity = state === 'absent' ? 0.15 : 0.7
    } else {
      n.ring.material.color.set(n.baseRing)
      n.ring.material.opacity = n.baseRingOpacity
    }
    n.halo.visible = this.blinking.has(n.key)
  }

  drawFlows(flows) {
    for (const o of this.flowObjs) { if (!o.mesh) continue; this.liveLayer.remove(o.mesh); o.mesh.geometry.dispose(); o.mesh.material.dispose() }
    this.flowObjs = []
    this.flowParts = []
    this.lastFlows = flows
    const merge = flows.length > MERGE_FLOWS_ABOVE
    const groups = new Map() // merged mode: colour|recent -> { geos, color, opacity }
    let budget = MAX_PARTICLES
    for (const f of flows) {
      const a = this.nodes.get(f.src), b = this.nodes.get(f.dst)
      if (!a || !b || a === b) continue
      const curve = this.arc(a.top, b.top, 0.18, 0.5)
      const sev = Math.min(4, f.max_severity || 0)
      const color = C(SEV_COLOR[sev])
      const r = flowRadius(f.total)
      const baseOpacity = f.recent ? 0.55 : 0.22
      const geo = new THREE.TubeGeometry(curve, merge ? 20 : 40, r, merge ? 6 : 8, false)
      if (merge) {
        const k = `${SEV_COLOR[sev]}|${f.recent ? 1 : 0}`
        const g = groups.get(k) || { geos: [], color, opacity: baseOpacity }
        g.geos.push(geo)
        groups.set(k, g)
        // keep one record per flow for selection, snapshot and the node panel, without its own mesh
        this.flowObjs.push({ kind: 'flowref', src: f.src, dst: f.dst, flow: f, radius: r, curve })
      } else {
        const tube = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ color, transparent: true, opacity: baseOpacity, depthWrite: false }))
        tube.userData.flow = f
        this.liveLayer.add(tube)
        this.flowObjs.push({ kind: 'tube', mesh: tube, src: f.src, dst: f.dst, baseOpacity, flow: f, radius: r, curve })
      }
      const n = Math.min(budget, flowParticles(f.recent))
      budget -= n
      const pc = color.clone().lerp(C(0xffffff), 0.35)
      // direction follows the connection: from the source (client) to the destination (server)
      for (let i = 0; i < n; i++) this.flowParts.push({ curve, t: i / n, speed: 0.12 + Math.min(0.5, f.recent / 60), scale: Math.max(0.14, r * 1.4), color: pc })
    }
    for (const g of groups.values()) {
      const mesh = new THREE.Mesh(mergeGeometries(g.geos, false), new THREE.MeshBasicMaterial({ color: g.color, transparent: true, opacity: g.opacity, depthWrite: false }))
      for (const x of g.geos) x.dispose()
      this.liveLayer.add(mesh)
      this.flowObjs.push({ kind: 'merged', mesh, baseOpacity: g.opacity })
    }
    this.syncPool(this.flowPool, this.flowParts)
  }

  /** Merged tubes cannot be dimmed one by one, so the selected node's own links are drawn again on top. */
  drawFlowHighlight(key) {
    for (const o of this.flowObjs.filter((x) => x.kind === 'highlight')) { this.liveLayer.remove(o.mesh); o.mesh.geometry.dispose(); o.mesh.material.dispose() }
    this.flowObjs = this.flowObjs.filter((x) => x.kind !== 'highlight')
    if (!key) return
    for (const f of this.flowObjs.filter((x) => x.kind === 'flowref' && (x.src === key || x.dst === key))) {
      const mesh = new THREE.Mesh(new THREE.TubeGeometry(f.curve, 40, f.radius, 8, false),
        new THREE.MeshBasicMaterial({ color: C(SEV_COLOR[Math.min(4, f.flow.max_severity || 0)]), transparent: true, opacity: 0.75, depthWrite: false }))
      this.liveLayer.add(mesh)
      this.flowObjs.push({ kind: 'highlight', mesh })
    }
  }

  syncPool(pool, parts) {
    pool.count = parts.length
    parts.forEach((p, i) => pool.setColorAt(i, p.color))
    if (pool.instanceColor) pool.instanceColor.needsUpdate = true
  }

  drawAttack(attack) {
    for (const o of this.attackObjs) { this.liveLayer.remove(o.mesh); this.disposeTree(o.mesh) }
    this.attackObjs = []
    this.attackParts = []
    this.syncPool(this.attackPool, this.attackParts)
    if (!attack) return
    const from = this.nodes.get(attack.attacker)
    if (!from) return
    const marker = new THREE.Mesh(new THREE.TorusGeometry(2.8, 0.1, 8, 56), new THREE.MeshBasicMaterial({ color: 0xf43f5e }))
    marker.rotation.x = Math.PI / 2
    marker.position.set(from.top.x, 0.15, from.top.z)
    this.liveLayer.add(marker)
    this.attackObjs.push({ kind: 'marker', mesh: marker })
    for (const s of attack.steps) {
      if (s.phase === 'pending') continue
      const active = s.phase === 'active'
      for (const k of s.targets) {
        const to = this.nodes.get(k)
        if (!to || to === from) continue
        const curve = this.arc(from.top, to.top, 0.3, 2)
        if ((s.isolated_targets || []).includes(k)) {
          // attempted but unreachable: lab subnets are isolated from each other, so draw a grey dashed attempt, not a hit
          const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(40))
          const dashed = new THREE.Line(geo, new THREE.LineDashedMaterial({ color: 0x64748b, dashSize: 0.6, gapSize: 0.4, transparent: true, opacity: active ? 0.9 : 0.4 }))
          dashed.computeLineDistances()
          dashed.userData.step = s.index
          this.liveLayer.add(dashed)
          this.attackObjs.push({ kind: 'isolated', mesh: dashed, step: s.index, target: k })
          continue
        }
        const line = new THREE.Mesh(new THREE.TubeGeometry(curve, 40, active ? 0.12 : 0.045, 6, false),
          new THREE.MeshBasicMaterial({ color: active ? 0xff3b5c : 0x9f1239, transparent: true, opacity: active ? 0.9 : 0.35, depthWrite: false }))
        line.userData.step = s.index
        this.liveLayer.add(line)
        this.attackObjs.push({ kind: 'path', mesh: line, active, step: s.index })
        if (!active) continue
        for (let i = 0; i < 3 && this.attackParts.length < MAX_ATTACK_PARTICLES; i++) {
          this.attackParts.push({ curve, t: i / 3, speed: 0.55, scale: 1, color: C(0xffd1d9), orient: true })
        }
      }
    }
    this.syncPool(this.attackPool, this.attackParts)
  }

  // ------------------------------------------------------------------ input, frame loop
  pick(e, kind) {
    const r = this.renderer.domElement.getBoundingClientRect()
    this.pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1)
    this.raycaster.setFromCamera(this.pointer, this.camera)
    const hit = this.raycaster.intersectObjects([...this.nodes.values()].map((n) => n.group), true)[0]
    this.renderer.domElement.style.cursor = hit ? 'pointer' : 'grab'
    if (kind === 'move') return
    const key = hit?.object.userData.key || null
    if (kind === 'dbl' && key) { this.focus(key); return }
    this.select(key)
    this.onSelect(key)
  }

  /**
   * Panels covering the left/right edge (px). The projection is shifted so the scene's centre sits in the middle of the
   * visible part of the canvas instead of behind a panel.
   */
  setInsets({ left = 0, right = 0 } = {}) {
    this.insets = { left, right }
    this.resize()
  }

  resize() {
    const { clientWidth: w, clientHeight: h } = this.container
    if (!w || !h) return
    const { left = 0, right = 0 } = this.insets || {}
    this.camera.aspect = w / h
    if (left || right) this.camera.setViewOffset(w, h, (right - left) / 2, 0, w, h)
    else this.camera.clearViewOffset()
    this.camera.updateProjectionMatrix()
    this.renderer.setSize(w, h)
    this.labelRenderer.setSize(w, h)
  }

  loop() {
    if (!this.running) return
    this.raf = requestAnimationFrame(() => this.loop())
    const dt = Math.min(0.1, this.clock.getDelta())
    this.t += dt
    if (this.tween) {
      const tw = this.tween
      tw.t = Math.min(1, tw.t + dt / tw.dur)
      const k = tw.t < 0.5 ? 2 * tw.t * tw.t : 1 - (-2 * tw.t + 2) ** 2 / 2
      this.camera.position.lerpVectors(tw.fromCam, tw.toCam, k)
      this.controls.target.lerpVectors(tw.fromTgt, tw.toTgt, k)
      if (tw.t >= 1) this.tween = null
    }
    for (const p of this.decor) {
      p.t = (p.t + dt * p.speed) % 1
      p.mesh.position.copy(p.curve.getPoint(p.dir > 0 ? p.t : 1 - p.t))
    }
    this.animatePool(this.flowPool, this.flowParts, dt)
    this.animatePool(this.attackPool, this.attackParts, dt)
    const blink = 0.5 + 0.5 * Math.sin(this.t * 8)
    for (const [k, n] of this.nodes) {
      if (k === this.selected) n.group.rotation.y += dt * 0.6
      if (n.halo.visible) {
        n.halo.material.opacity = 0.04 + blink * 0.14
        n.ring.material.color.set(0xf43f5e)
        n.ring.material.opacity = 0.3 + blink * 0.7
        for (const m of n.mats.body) { m.emissive.set(0xf43f5e); m.emissiveIntensity = 0.15 + blink * 0.55 }
      }
      if (this.live && n.state === 'pending') for (const m of n.mats.led) m.color.set(blink > 0.5 ? 0xf59e0b : 0x3b2a05)
      n.group.traverse((o) => { if (o.userData.spin) o.rotation.z += dt })
    }
    for (const o of this.attackObjs) if (o.kind === 'path' && o.active) o.mesh.material.opacity = 0.55 + blink * 0.45
    if (this.compact && this.labels && (this.frameNo = (this.frameNo || 0) + 1) % 6 === 0) {
      const ref = this.camera.position.distanceTo(this.controls.target) * 1.15
      for (const [k, n] of this.nodes) n.label.visible = k === this.selected || n.halo.visible || this.camera.position.distanceTo(n.pos) < ref
    }
    this.controls.update()
    this.renderer.render(this.scene, this.camera)
    this.labelRenderer.render(this.scene, this.camera)
  }

  animatePool(pool, parts, dt) {
    if (!parts.length) return
    const up = this.tmpV.set(0, 0, 1)
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i]
      p.t = (p.t + dt * p.speed) % 1
      const pos = p.curve.getPoint(p.t)
      if (p.orient) this.tmpQ.setFromUnitVectors(up, p.curve.getTangent(p.t).normalize())
      else this.tmpQ.identity()
      this.tmpM.compose(pos, this.tmpQ, this.tmpS.setScalar(p.scale))
      pool.setMatrixAt(i, this.tmpM)
    }
    pool.instanceMatrix.needsUpdate = true
  }

  /** Test hook: plain summary of what is on screen (used by the browser checks, not by the UI). */
  snapshot() {
    return {
      nodes: Object.fromEntries([...this.nodes].map(([k, n]) => [k, { state: n.state, blinking: n.halo.visible, ghost: n.ghost }])),
      flows: this.flowObjs.filter((o) => o.kind === 'tube' || o.kind === 'flowref').map((o) => ({ src: o.src, dst: o.dst, radius: o.radius, total: o.flow.total })),
      particles: this.flowParts.length,
      mergedFlows: this.flowObjs.some((o) => o.kind === 'merged'),
      attackPaths: this.attackObjs.filter((o) => o.kind === 'path').map((o) => ({ step: o.step, active: o.active })),
      isolatedPaths: this.attackObjs.filter((o) => o.kind === 'isolated').map((o) => ({ step: o.step, target: o.target })),
      selected: this.selected,
      target: this.controls.target.toArray().map((v) => +v.toFixed(2)),
    }
  }

  dispose() {
    this.running = false
    cancelAnimationFrame(this.raf)
    this.ro.disconnect()
    this.renderer.domElement.removeEventListener('click', this._onClick)
    this.renderer.domElement.removeEventListener('dblclick', this._onDbl)
    this.renderer.domElement.removeEventListener('pointermove', this._onMove)
    this.clearWorld()
    for (const pool of [this.flowPool, this.attackPool]) { pool.geometry.dispose(); pool.material.dispose(); pool.dispose() }
    this.controls.dispose()
    this.renderer.dispose()
    this.renderer.domElement.remove()
    this.labelRenderer.domElement.remove()
  }
}

function escape(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}
