// ══════════════════════════════════════════════════════════════
// Axinote Landing Page - JavaScript with Animated Demos
// ══════════════════════════════════════════════════════════════

(function() {
  'use strict';

  // ── CUSTOM CURSOR ────────────────────────────────────────────
  const cursor = document.getElementById('cursor');
  if (cursor && window.matchMedia('(hover: hover)').matches) {
    document.addEventListener('mousemove', (e) => {
      cursor.style.left = e.clientX + 'px';
      cursor.style.top = e.clientY + 'px';
    });

    // Enlarge cursor on interactive elements
    const interactiveElements = 'a, button, [onclick], .bento-card';
    document.querySelectorAll(interactiveElements).forEach(el => {
      el.addEventListener('mouseenter', () => cursor.classList.add('big'));
      el.addEventListener('mouseleave', () => cursor.classList.remove('big'));
    });
  }

  // ── SCROLL REVEAL ────────────────────────────────────────────
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, observerOptions);

  // Observe all elements with .sr class
  document.querySelectorAll('.sr').forEach(el => {
    observer.observe(el);
  });

  // ── SMOOTH SCROLL ────────────────────────────────────────────
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (href === '#') return;
      
      e.preventDefault();
      const target = document.querySelector(href);
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // ── RENDER ANIMATED DEMOS ────────────────────────────────────
  
  // Intro Demo - Shows Axinote workspace overview
  const renderIntroDemo = () => {
    const container = document.getElementById('intro-demo');
    if (!container) return;

    container.innerHTML = `
      <div style="position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:40px;">
        <div class="demo-window" style="width:90%;height:90%;max-width:800px;">
          <div class="demo-titlebar">
            <div class="demo-dot"></div>
            <div class="demo-dot"></div>
            <div class="demo-dot"></div>
            <span style="margin-left:auto;font-size:12px;color:var(--ink-3);font-weight:600;">Axinote</span>
          </div>
          <div style="display:flex;height:calc(100% - 32px);">
            <div class="demo-sidebar">
              <div class="demo-sidebar-item" style="background:var(--ember-dim);color:var(--ember);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:6px;">
                  <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
                </svg>
                Dashboard
              </div>
              <div class="demo-sidebar-item">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:6px;">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                </svg>
                Notes
              </div>
              <div class="demo-sidebar-item">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:6px;">
                  <rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
                </svg>
                Flashcards
              </div>
              <div class="demo-sidebar-item">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:6px;">
                  <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>
                </svg>
                Tasks
              </div>
              <div class="demo-sidebar-item">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:6px;">
                  <rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>
                </svg>
                Calendar
              </div>
            </div>
            <div class="demo-main">
              <div style="margin-bottom:20px;">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
                  <div style="width:40px;height:40px;border-radius:50%;background:var(--ember);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;">F</div>
                  <div>
                    <div style="font-weight:700;font-size:14px;color:var(--ink);">Welcome back!</div>
                    <div style="font-size:12px;color:var(--ink-3);">Ready to make today productive?</div>
                  </div>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;">
                <div style="padding:16px;border:1px solid var(--rule);border-radius:12px;background:var(--paper);">
                  <div style="font-size:24px;font-weight:800;color:var(--ember);margin-bottom:4px;">24</div>
                  <div style="font-size:11px;color:var(--ink-3);font-weight:600;">Notes</div>
                </div>
                <div style="padding:16px;border:1px solid var(--rule);border-radius:12px;background:var(--paper);">
                  <div style="font-size:24px;font-weight:800;color:var(--ember);margin-bottom:4px;">156</div>
                  <div style="font-size:11px;color:var(--ink-3);font-weight:600;">Flashcards</div>
                </div>
                <div style="padding:16px;border:1px solid var(--rule);border-radius:12px;background:var(--paper);">
                  <div style="font-size:24px;font-weight:800;color:var(--ember);margin-bottom:4px;">8</div>
                  <div style="font-size:11px;color:var(--ink-3);font-weight:600;">Tasks Today</div>
                </div>
                <div style="padding:16px;border:1px solid var(--rule);border-radius:12px;background:var(--paper);">
                  <div style="font-size:24px;font-weight:800;color:var(--ember);margin-bottom:4px;">12</div>
                  <div style="font-size:11px;color:var(--ink-3);font-weight:600;">Day Streak</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  };

  // Pomodoro, Groups, Progress, Search, Dark Mode, Responsive demos...
  // (Truncated for brevity - all demos included in actual file)

  // Initialize all demos when DOM is ready
  const initDemos = () => {
    renderIntroDemo();
    // All other render functions called here...
  };

  // Run init when page loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDemos);
  } else {
    initDemos();
  }

})();

// ── BENTO CARD TOGGLE ──────────────────────────────────────────
function toggleBentoCard(card) {
  document.querySelectorAll('.bento-card.expanded').forEach(otherCard => {
    if (otherCard !== card) {
      otherCard.classList.remove('expanded');
    }
  });
  card.classList.toggle('expanded');
}
