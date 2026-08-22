// <gk-gate-3d> — 54 distributions travelling toward an aperture. Three never pass it.
// Blueprint palette to match the GateKeeper spec sheet.
class GkGate3D extends HTMLElement {
  connectedCallback() {
    if (this._booted) return;
    this._booted = true;
    this.style.display = 'block';
    this.style.position = 'relative';
    this.style.height = '100%';
    const canvas = document.createElement('canvas');
    canvas.style.cssText = 'width:100%;height:100%;display:block';
    this.appendChild(canvas);
    this._canvas = canvas;
    this._start();
  }

  disconnectedCallback() {
    cancelAnimationFrame(this._raf);
    if (this._ro) this._ro.disconnect();
    if (this._renderer) this._renderer.dispose();
  }

  async _start() {
    const THREE = await import('https://unpkg.com/three@0.184.0/build/three.module.js');
    const canvas = this._canvas;
    const w = this.clientWidth || 900;
    const h = this.clientHeight || 440;

    const BLUE = 0x4C6BFF, BONE = 0xE8E4DC, DIM = 0x6E6A62, RED = 0xFF5A3C, LIME = 0xA8E01F;
    const Z_START = -8.5, Z_END = 5.2, GATE_Z = -0.28;

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(w, h, false);
    this._renderer = renderer;

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x101010, 7, 17);
    const camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 60);
    const CAM = new THREE.Vector3(3.9, 2.15, 7.4);
    camera.position.copy(CAM);
    camera.lookAt(0, 0, -0.6);

    const world = new THREE.Group();
    scene.add(world);

    // ── the aperture ────────────────────────────────────────────────
    const gate = new THREE.Group();
    gate.position.z = 0;
    world.add(gate);

    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(1.72, 0.016, 8, 140),
      new THREE.MeshBasicMaterial({ color: BLUE })
    );
    ring.name = 'gate_ring';
    gate.add(ring);

    const ringOuter = new THREE.Mesh(
      new THREE.TorusGeometry(2.02, 0.006, 6, 140),
      new THREE.MeshBasicMaterial({ color: BLUE, transparent: true, opacity: .45 })
    );
    gate.add(ringOuter);

    const ringInner = new THREE.Mesh(
      new THREE.TorusGeometry(1.44, 0.004, 6, 120),
      new THREE.MeshBasicMaterial({ color: BONE, transparent: true, opacity: .18 })
    );
    gate.add(ringInner);

    // registration ticks around the aperture
    const tickGeo = new THREE.BoxGeometry(0.015, 0.13, 0.015);
    const tickMat = new THREE.MeshBasicMaterial({ color: BLUE, transparent: true, opacity: .7 });
    const tickMatMajor = new THREE.MeshBasicMaterial({ color: BONE, transparent: true, opacity: .8 });
    for (let i = 0; i < 32; i++) {
      const a = (i / 32) * Math.PI * 2;
      const major = i % 8 === 0;
      const t = new THREE.Mesh(tickGeo, major ? tickMatMajor : tickMat);
      const rad = 1.87;
      t.position.set(Math.cos(a) * rad, Math.sin(a) * rad, 0);
      t.rotation.z = a - Math.PI / 2;
      if (major) t.scale.set(1.6, 1.5, 1.6);
      gate.add(t);
    }

    // crosshair through the aperture centre
    const cross = new THREE.LineSegments(
      new THREE.BufferGeometry().setAttribute('position', new THREE.Float32BufferAttribute(
        [-0.22, 0, 0, 0.22, 0, 0, 0, -0.22, 0, 0, 0.22, 0], 3)),
      new THREE.LineBasicMaterial({ color: BONE, transparent: true, opacity: .35 })
    );
    gate.add(cross);

    // ── blueprint floor ─────────────────────────────────────────────
    const grid = new THREE.GridHelper(26, 26, BLUE, BLUE);
    grid.position.set(0, -2.35, -2);
    grid.material.transparent = true;
    grid.material.opacity = .07;
    world.add(grid);

    // ── nodes ───────────────────────────────────────────────────────
    const COUNT = 54;
    const FLAGGED = new Set([9, 26, 44]);
    const geoSmall = new THREE.SphereGeometry(0.062, 14, 14);
    const geoBig = new THREE.SphereGeometry(0.105, 18, 18);
    const matPending = new THREE.MeshStandardMaterial({ name: 'pending', color: DIM, roughness: .65, metalness: .05 });
    const matPendingLit = new THREE.MeshStandardMaterial({ name: 'pending_lit', color: BONE, roughness: .5, metalness: .08 });
    const matPass = new THREE.MeshStandardMaterial({ name: 'admitted', color: LIME, emissive: LIME, emissiveIntensity: .3, roughness: .4 });
    const matBlock = new THREE.MeshStandardMaterial({ name: 'blocked', color: RED, emissive: RED, emissiveIntensity: .75, roughness: .35 });

    const nodes = [];
    const trailPos = new Float32Array(COUNT * 6);
    const GOLD = Math.PI * (3 - Math.sqrt(5));

    for (let i = 0; i < COUNT; i++) {
      const bad = FLAGGED.has(i);
      const rad = Math.sqrt((i + 0.5) / COUNT) * 1.34;
      const th = GOLD * i;
      const mesh = new THREE.Mesh(bad ? geoBig : geoSmall, bad ? matBlock : (i % 4 === 0 ? matPendingLit : matPending));
      mesh.name = bad ? 'blocked_package_' + i : 'package_' + i;
      const z = Z_START + ((i / COUNT) * (Z_END - Z_START));
      mesh.position.set(Math.cos(th) * rad, Math.sin(th) * rad, z);
      world.add(mesh);
      nodes.push({
        mesh, bad, rad, th,
        speed: 0.72 + ((i * 37) % 11) / 22,
        held: 0,
        passed: z > GATE_Z,
        wobble: (i % 7) * 0.9
      });
    }

    const trailGeo = new THREE.BufferGeometry();
    trailGeo.setAttribute('position', new THREE.BufferAttribute(trailPos, 3));
    const trails = new THREE.LineSegments(trailGeo, new THREE.LineBasicMaterial({ color: BONE, transparent: true, opacity: .16 }));
    trails.name = 'trails';
    world.add(trails);

    // rejection pulses
    const pulses = [];
    for (let i = 0; i < 3; i++) {
      const p = new THREE.Mesh(
        new THREE.TorusGeometry(0.3, 0.012, 6, 48),
        new THREE.MeshBasicMaterial({ color: RED, transparent: true, opacity: 0 })
      );
      p.visible = false;
      world.add(p);
      pulses.push(p);
    }

    // ── light ───────────────────────────────────────────────────────
    scene.add(new THREE.AmbientLight(0xffffff, .5));
    const key = new THREE.DirectionalLight(0xffffff, 1.05);
    key.position.set(4, 6, 8);
    scene.add(key);
    const fill = new THREE.PointLight(BLUE, 14, 14);
    fill.position.set(-3, 1.2, 1.5);
    scene.add(fill);

    // ── pointer parallax ────────────────────────────────────────────
    const target = { x: 0, y: 0 };
    const cur = { x: 0, y: 0 };
    this.addEventListener('pointermove', e => {
      const r = this.getBoundingClientRect();
      target.x = ((e.clientX - r.left) / r.width - 0.5) * 1.5;
      target.y = ((e.clientY - r.top) / r.height - 0.5) * -0.9;
    });
    this.addEventListener('pointerleave', () => { target.x = 0; target.y = 0; });

    this._ro = new ResizeObserver(() => {
      const nw = this.clientWidth, nh = this.clientHeight;
      if (!nw || !nh) return;
      renderer.setSize(nw, nh, false);
      camera.aspect = nw / nh;
      camera.updateProjectionMatrix();
    });
    this._ro.observe(this);

    let prev = performance.now() / 1000;
    let pulseIdx = 0;
    const tick = () => {
      const now = performance.now() / 1000;
      const dt = Math.min(now - prev, 0.05);
      prev = now;

      cur.x += (target.x - cur.x) * 0.05;
      cur.y += (target.y - cur.y) * 0.05;
      camera.position.set(CAM.x + cur.x, CAM.y + cur.y, CAM.z);
      camera.lookAt(0, 0, -0.6);

      ring.rotation.z = now * 0.12;
      ringOuter.rotation.z = -now * 0.07;
      const breathe = 1 + Math.sin(now * 1.4) * 0.012;
      ring.scale.setScalar(breathe);

      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        const m = n.mesh;
        const z0 = m.position.z;

        if (n.bad && n.held > 0) {
          n.held -= dt;
          const k = 1 + Math.sin(now * 9) * 0.14;
          m.scale.setScalar(k);
          if (n.held <= 0) {
            m.position.z = Z_START;
            m.scale.setScalar(1);
            n.passed = false;
          }
        } else {
          m.position.z += n.speed * dt * 1.35;
        }

        // drift so the field never looks static
        const drift = 0.045;
        m.position.x = Math.cos(n.th + Math.sin(now * 0.25 + n.wobble) * 0.09) * n.rad + Math.sin(now * 0.6 + n.wobble) * drift;
        m.position.y = Math.sin(n.th + Math.sin(now * 0.25 + n.wobble) * 0.09) * n.rad + Math.cos(now * 0.5 + n.wobble) * drift;

        if (n.bad && !n.passed && m.position.z >= GATE_Z && n.held <= 0) {
          m.position.z = GATE_Z;
          n.held = 1.7;
          const p = pulses[pulseIdx++ % pulses.length];
          p.position.set(m.position.x, m.position.y, GATE_Z);
          p.visible = true;
          p.userData.t = 0;
        }

        if (!n.bad && !n.passed && m.position.z > 0) {
          n.passed = true;
          m.material = matPass;
        }

        if (m.position.z > Z_END) {
          m.position.z = Z_START;
          n.passed = false;
          m.material = (i % 4 === 0) ? matPendingLit : matPending;
        }

        // scale in/out at the extremes so nothing pops
        const edge = Math.min(1, (m.position.z - Z_START) / 1.6, (Z_END - m.position.z) / 1.6);
        if (!(n.bad && n.held > 0)) m.scale.setScalar(Math.max(0.05, edge));

        const o = i * 6;
        trailPos[o] = m.position.x; trailPos[o + 1] = m.position.y; trailPos[o + 2] = z0 - 0.34;
        trailPos[o + 3] = m.position.x; trailPos[o + 4] = m.position.y; trailPos[o + 5] = m.position.z;
      }
      trailGeo.attributes.position.needsUpdate = true;

      for (const p of pulses) {
        if (!p.visible) continue;
        p.userData.t += dt;
        const t = p.userData.t / 1.2;
        if (t >= 1) { p.visible = false; continue; }
        p.scale.setScalar(0.6 + t * 3.4);
        p.material.opacity = (1 - t) * 0.7;
      }

      renderer.render(scene, camera);
      this._raf = requestAnimationFrame(tick);
    };
    tick();
  }
}

if (!customElements.get('gk-gate-3d')) customElements.define('gk-gate-3d', GkGate3D);
