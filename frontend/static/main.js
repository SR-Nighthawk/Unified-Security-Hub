/* SecHub — Dark Ops Terminal UI layer (Vanilla JS)
   - Cursor crosshair + trailing dots
   - Background parallax grid
   - Parallax card tilt w/ specular highlight
   - Threat ticker (CIRCL CVE + local recent scans)
   - Stat count-up animation
   - Command palette (press /)
   - AI chat helpers: highlight.js + copy buttons + typing indicator hooks
*/

(() => {
  const qs = (sel, root = document) => root.querySelector(sel);
  const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const nowUtc = () => new Date();
  const pad2 = (n) => String(n).padStart(2, "0");

  function formatUtcClock(d) {
    return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  }

  function relativeTimeFromEpochMs(ms) {
    const diff = Date.now() - ms;
    if (!isFinite(diff) || diff < 0) return "just now";
    const s = Math.floor(diff / 1000);
    if (s < 10) return "just now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m} min ago`;
    const h = Math.floor(m / 60);
    if (h < 48) return `${h} hr ago`;
    const d = Math.floor(h / 24);
    return `${d} d ago`;
  }

  function parseCtimeToEpochMs(s) {
    // app.py currently returns time.ctime(): "Tue Apr 14 12:34:56 2026"
    // Date.parse can usually parse it; fallback to "unknown".
    const t = Date.parse(s);
    return Number.isFinite(t) ? t : NaN;
  }

  // -----------------------------
  // HUD clocks
  // -----------------------------
  function initClocks() {
    const hud = qs("#hud-clock");
    const footer = qs("#footer-time");
    const tick = () => {
      const d = nowUtc();
      const t = formatUtcClock(d);
      if (hud) hud.textContent = t;
      if (footer) footer.textContent = `${t} UTC`;
    };
    tick();
    window.setInterval(tick, 1000);
  }

  // -----------------------------
  // Background parallax grid
  // -----------------------------
  function initBgParallax() {
    const grid = qs(".bg-grid");
    if (!grid) return;

    let mx = 0, my = 0, tx = 0, ty = 0;
    const max = 20;

    window.addEventListener("mousemove", (e) => {
      mx = (e.clientX / window.innerWidth - 0.5) * 2;
      my = (e.clientY / window.innerHeight - 0.5) * 2;
    }, { passive: true });

    const raf = () => {
      // move opposite to mouse
      tx += ((-mx * max) - tx) * 0.08;
      ty += ((-my * max) - ty) * 0.08;
      grid.style.transform = `translate3d(${tx}px, ${ty}px, 0)`;
      requestAnimationFrame(raf);
    };
    requestAnimationFrame(raf);
  }

  // -----------------------------
  // Cursor crosshair + trail
  // -----------------------------
  function initCursor() {
    // Disable on touch devices
    if (window.matchMedia("(pointer: coarse)").matches) return;

    try {
      const root = document.body;
      if (!root) return;

      const cross = document.createElement("div");
      cross.className = "cursor-crosshair";
      cross.setAttribute("aria-hidden", "true");
      root.appendChild(cross);

      const trailCount = 10;
      const dots = [];
      for (let i = 0; i < trailCount; i++) {
        const d = document.createElement("div");
        d.className = "cursor-dot";
        d.setAttribute("aria-hidden", "true");
        d.style.setProperty("--i", String(i));
        root.appendChild(d);
        dots.push({ el: d, x: 0, y: 0 });
      }

      // Safety: keep normal cursor enabled.
      // (The crosshair/trail are additive; we do not hide the OS cursor.)
      document.documentElement.classList.remove("cursor-on");

      let x = window.innerWidth / 2;
      let y = window.innerHeight / 2;
      let vx = x, vy = y;

      window.addEventListener("mousemove", (e) => {
        x = e.clientX;
        y = e.clientY;
      }, { passive: true });

      const raf = () => {
        cross.style.transform = `translate3d(${x}px, ${y}px, 0)`;

        vx += (x - vx) * 0.22;
        vy += (y - vy) * 0.22;
        let px = vx, py = vy;
        for (let i = 0; i < dots.length; i++) {
          const t = dots[i];
          const k = Math.max(0.04, 0.22 - i * 0.012);
          t.x += (px - t.x) * k;
          t.y += (py - t.y) * k;
          px = t.x;
          py = t.y;
          t.el.style.transform = `translate3d(${t.x}px, ${t.y}px, 0)`;
        }
        requestAnimationFrame(raf);
      };
      requestAnimationFrame(raf);
    } catch (_) {
      // Fail-safe: never trap user with hidden cursor
      document.documentElement.classList.remove("cursor-on");
    }
  }

  // -----------------------------
  // Card tilt + specular highlight
  // -----------------------------
  function initTilt() {
    const cards = qsa("[data-tilt], .tilt");
    if (!cards.length) return;

    const maxTilt = 12;

    cards.forEach((card) => {
      let rect = null;
      const onEnter = () => { rect = card.getBoundingClientRect(); card.classList.add("tilting"); };
      const onLeave = () => {
        card.classList.remove("tilting");
        card.style.transform = "";
        card.style.setProperty("--mx", "50%");
        card.style.setProperty("--my", "50%");
      };

      const onMove = (e) => {
        if (!rect) rect = card.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const dx = (e.clientX - cx) / (rect.width / 2);
        const dy = (e.clientY - cy) / (rect.height / 2);
        const rx = clamp(-dy * maxTilt, -maxTilt, maxTilt);
        const ry = clamp(dx * maxTilt, -maxTilt, maxTilt);
        card.style.transform = `perspective(800px) rotateX(${rx}deg) rotateY(${ry}deg) translateZ(0)`;

        const px = clamp(((e.clientX - rect.left) / rect.width) * 100, 0, 100);
        const py = clamp(((e.clientY - rect.top) / rect.height) * 100, 0, 100);
        card.style.setProperty("--mx", `${px}%`);
        card.style.setProperty("--my", `${py}%`);
      };

      card.addEventListener("mouseenter", onEnter);
      card.addEventListener("mouseleave", onLeave);
      card.addEventListener("mousemove", onMove, { passive: true });
    });
  }

  // -----------------------------
  // Count-up stat animation
  // -----------------------------
  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function animateCount(el, to, duration = 1200) {
    const from = 0;
    const start = performance.now();
    const isInt = Number.isInteger(to);

    const step = (ts) => {
      const p = clamp((ts - start) / duration, 0, 1);
      const v = from + (to - from) * easeOutCubic(p);
      el.textContent = isInt ? String(Math.round(v)) : String(v.toFixed(0));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function initCountups() {
    const els = qsa("[data-count-to]");
    if (!els.length) return;
    els.forEach((el) => {
      const v = Number(el.getAttribute("data-count-to"));
      if (Number.isFinite(v)) animateCount(el, v, 1200);
    });
  }

  // -----------------------------
  // Threat ticker
  // -----------------------------
  const TICKER_REFRESH_MS = 5 * 60 * 1000;

  function buildTickerItem({ level, text, href }) {
    const span = document.createElement("span");
    span.className = `ticker-item ${level ? `lvl-${level}` : ""}`.trim();
    span.textContent = text;
    if (href) {
      const a = document.createElement("a");
      a.href = href;
      a.target = "_blank";
      a.rel = "noreferrer";
      a.className = "ticker-link";
      a.appendChild(span);
      return a;
    }
    return span;
  }

  async function loadThreatTicker() {
    const track = qs("#threat-ticker");
    if (!track) return;

    const items = [];

    // Local scan intel (recent scans + APT feed)
    try {
      const r = await fetch("/api/dashboard-stats", { cache: "no-store" });
      const d = await r.json();

      if (Array.isArray(d?.recent_scans) && d.recent_scans.length) {
        const last = d.recent_scans[0];
        const whenMs = parseCtimeToEpochMs(last.time);
        const rt = Number.isFinite(whenMs) ? relativeTimeFromEpochMs(whenMs) : "recently";
        items.push({
          level: "info",
          text: `[OPS] Last scan: ${last.tool} · ${last.target} · ${rt}`,
        });
      }

      if (Array.isArray(d?.apt_feed) && d.apt_feed.length) {
        const hot = d.apt_feed
          .filter((g) => (g.threat || "").toUpperCase() === "CRITICAL" || (g.threat || "").toUpperCase() === "HIGH")
          .slice(0, 3);
        hot.forEach((g) => {
          items.push({
            level: (g.threat || "high").toLowerCase(),
            text: `[${(g.threat || "HIGH").toUpperCase()}] ${g.name} · ${g.country} · ${g.links} nodes`,
          });
        });
      }
    } catch (_) {
      // ignore
    }

    // CVE feed (CIRCL)
    try {
      const r = await fetch("https://cve.circl.lu/api/last/10", { cache: "no-store" });
      const d = await r.json();
      if (Array.isArray(d)) {
        d.slice(0, 10).forEach((c) => {
          const id = c?.id || "CVE";
          const sum = (c?.summary || "").replace(/\s+/g, " ").trim();
          const short = sum.length > 90 ? `${sum.slice(0, 90)}…` : sum;
          items.push({
            level: "critical",
            text: `[CRITICAL] ${id} | ${short || "New vulnerability published"}`,
            href: `https://cve.circl.lu/cve/${encodeURIComponent(id)}`
          });
        });
      }
    } catch (_) {
      items.push({ level: "muted", text: `[INFO] CVE feed unavailable · operating from local intel cache` });
    }

    // Render
    track.innerHTML = "";
    const frag = document.createDocumentFragment();

    // If too few items, duplicate to make seamless marquee
    const base = items.length ? items : [{ level: "muted", text: "Threat feed idle — awaiting intel." }];
    const looped = base.length < 8 ? base.concat(base) : base;

    looped.forEach((it, idx) => {
      frag.appendChild(buildTickerItem(it));
      if (idx !== looped.length - 1) {
        const sep = document.createElement("span");
        sep.className = "ticker-sep";
        sep.textContent = "·";
        frag.appendChild(sep);
      }
    });
    track.appendChild(frag);
    track.setAttribute("data-ready", "1");
  }

  function initThreatTicker() {
    loadThreatTicker();
    window.setInterval(loadThreatTicker, TICKER_REFRESH_MS);
  }

  // -----------------------------
  // Command palette (CMDK)
  // -----------------------------
  function initCmdk() {
    const overlay = qs("#cmdk-overlay");
    const input = qs("#cmdk-input");
    const results = qs("#cmdk-results");
    const closeBtn = qs("#cmdk-close");
    if (!overlay || !input || !results) return;

    const commands = [
      { label: "Command Center", hint: "/", href: "/" },
      { label: "Network Scanner", hint: "/network-scanner", href: "/network-scanner" },
      { label: "Web Scanner", hint: "/web-scanner", href: "/web-scanner" },
      { label: "Dark Web Crawler", hint: "/darkweb", href: "/darkweb" },
      { label: "APT Tracker", hint: "/apt", href: "/apt" },
      { label: "AI Chat", hint: "/ai-chat", href: "/ai-chat" },
      { label: "Scan Reports", hint: "/reports", href: "/reports" },
      { label: "Analytics", hint: "/analytics", href: "/analytics" },
    ];

    let active = 0;
    let filtered = commands.slice();

    const render = () => {
      results.innerHTML = "";
      filtered.forEach((c, i) => {
        const row = document.createElement("div");
        row.className = `cmdk-row ${i === active ? "active" : ""}`;
        row.setAttribute("role", "option");
        row.tabIndex = -1;
        row.innerHTML = `
          <div class="cmdk-row-left">
            <div class="cmdk-row-ico"><i class="fas fa-chevron-right"></i></div>
            <div class="cmdk-row-label">${c.label}</div>
          </div>
          <div class="cmdk-row-hint mono muted">${c.hint}</div>
        `;
        row.addEventListener("mouseenter", () => { active = i; render(); });
        row.addEventListener("click", () => { window.location.href = c.href; });
        results.appendChild(row);
      });
      if (!filtered.length) {
        const empty = document.createElement("div");
        empty.className = "cmdk-empty";
        empty.textContent = "No matches.";
        results.appendChild(empty);
      }
    };

    const open = () => {
      overlay.hidden = false;
      overlay.classList.add("open");
      input.value = "";
      filtered = commands.slice();
      active = 0;
      render();
      window.setTimeout(() => input.focus(), 0);
    };

    const close = () => {
      overlay.classList.remove("open");
      overlay.hidden = true;
      input.value = "";
    };

    const updateFilter = () => {
      const q = input.value.trim().toLowerCase();
      filtered = commands.filter((c) => (c.label + " " + c.hint).toLowerCase().includes(q));
      active = 0;
      render();
    };

    input.addEventListener("input", updateFilter);
    input.addEventListener("keydown", (e) => {
      // Keep keyboard navigation consistent even while the input has focus.
      if (overlay.hidden) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        active = Math.min(active + 1, Math.max(0, filtered.length - 1));
        render();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        active = Math.max(active - 1, 0);
        render();
      } else if (e.key === "Enter") {
        e.preventDefault();
        const pick = filtered[active];
        if (pick) window.location.href = pick.href;
      } else if (e.key === "Escape") {
        e.preventDefault();
        close();
      }
    });

    overlay.addEventListener("mousedown", (e) => {
      if (e.target === overlay) close();
    });

    if (closeBtn) closeBtn.addEventListener("click", () => close());

    window.addEventListener("keydown", (e) => {
      // "/" opens (unless typing in input/textarea/contenteditable)
      const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
      const typing = tag === "input" || tag === "textarea" || e.target?.isContentEditable;
      if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        open();
        return;
      }
      if (e.key === "Escape" && !overlay.hidden) {
        e.preventDefault();
        close();
        return;
      }
      if (overlay.hidden) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        active = Math.min(active + 1, Math.max(0, filtered.length - 1));
        render();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        active = Math.max(active - 1, 0);
        render();
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filtered[active]) window.location.href = filtered[active].href;
      }
    });

    // Ensure it never starts open.
    overlay.hidden = true;
    overlay.classList.remove("open");
  }

  // -----------------------------
  // AI message UX: highlight + copy
  // -----------------------------
  function initHighlightAndCopy() {
    const root = qs("#chatMessages") || document;

    const enhance = () => {
      if (window.hljs) {
        qsa("pre code", root).forEach((code) => {
          if (code.dataset.hl === "1") return;
          code.dataset.hl = "1";
          try { window.hljs.highlightElement(code); } catch (_) {}
        });
      }

      // Add copy buttons to assistant message bubbles if present
      qsa(".msg.assistant .msg-body", root).forEach((body) => {
        if (body.dataset.copy === "1") return;
        body.dataset.copy = "1";
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "copy-btn";
        btn.innerHTML = `<i class="fas fa-copy"></i><span>Copy</span>`;
        btn.addEventListener("click", async () => {
          const text = body.innerText || "";
          try {
            await navigator.clipboard.writeText(text);
            btn.classList.add("ok");
            btn.innerHTML = `<i class="fas fa-check"></i><span>Copied</span>`;
            window.setTimeout(() => {
              btn.classList.remove("ok");
              btn.innerHTML = `<i class="fas fa-copy"></i><span>Copy</span>`;
            }, 900);
          } catch (_) {
            // ignore
          }
        });
        body.style.position = "relative";
        body.appendChild(btn);
      });
    };

    enhance();
    const mo = new MutationObserver(() => enhance());
    mo.observe(root, { childList: true, subtree: true });
  }

  // -----------------------------
  // Sidebar easter egg typing
  // -----------------------------
  function initSidebarEasterEgg() {
    const el = qs("#cli-typing");
    if (!el) return;
    const script = "deploy --profile=dark_ops --status";
    let i = 0;
    const type = () => {
      if (i <= script.length) {
        el.textContent = script.slice(0, i);
        i++;
        const jitter = 24 + Math.random() * 80;
        window.setTimeout(type, jitter);
      } else {
        // pause, then re-run subtly
        window.setTimeout(() => { i = 0; type(); }, 2400);
      }
    };
    window.setTimeout(type, 700);
  }

  // -----------------------------
  // Boot
  // -----------------------------
  function boot() {
    initClocks();
    initBgParallax();
    initCursor();
    initTilt();
    initCmdk();
    initThreatTicker();
    initHighlightAndCopy();
    initSidebarEasterEgg();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();

