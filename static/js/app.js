// Service worker (lets the site be added to the phone home screen)
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/static/service-worker.js").catch(() => {});
  });
}

const money = (n) => Number(n).toLocaleString("en-GH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

document.addEventListener("DOMContentLoaded", () => {
  // ---- Ask before actions marked with data-confirm ----
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  // ---- Stop double submission on every form (important for money actions) ----
  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", (event) => {
      requestAnimationFrame(() => {
        if (event.defaultPrevented) return;
        const btn = form.querySelector('button[type="submit"], input[type="submit"]');
        if (btn && !btn.disabled) {
          btn.dataset.originalText = btn.innerHTML;
          btn.disabled = true;
          btn.classList.add("opacity-70", "cursor-not-allowed");
          btn.innerHTML =
            '<span class="inline-flex items-center gap-2"><svg class="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">' +
            '<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>' +
            '<path class="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>Please wait…</span>';
        }
      });
    });
  });
  // The browser back button can restore a disabled button; put it right again.
  window.addEventListener("pageshow", (e) => {
    if (!e.persisted) return;
    document.querySelectorAll("button[disabled][data-original-text]").forEach((b) => {
      b.disabled = false;
      b.classList.remove("opacity-70", "cursor-not-allowed");
      b.innerHTML = b.dataset.originalText;
    });
  });

  // ---- Loan form: live cost preview, second guarantor, guarantor check ----
  const loanForm = document.querySelector("[data-loan-form]");
  if (loanForm) {
    const types = JSON.parse(loanForm.dataset.types || "[]");
    const typeInputs = loanForm.querySelectorAll('input[name="loan_type"]');
    const amountInput = loanForm.querySelector('[name="amount"]');
    const earningsInput = loanForm.querySelector('[name="g1_earnings"]');
    const preview = loanForm.querySelector("[data-loan-preview]");
    const second = loanForm.querySelector("[data-second-guarantor]");
    const secondNote = loanForm.querySelector("[data-second-note]");
    const downloadPdfBtn = document.getElementById("download-pdf-btn");

    // PDF/Print functionality
    if (downloadPdfBtn) {
      downloadPdfBtn.addEventListener("click", () => {
        const formData = new FormData(loanForm);

        // Open form in new window for printing
        const printWindow = window.open("", "_blank");

        if (printWindow) {
          fetch("/loans/guarantor-form", {
            method: "POST",
            body: formData
          })
          .then(response => response.text())
          .then(html => {
            printWindow.document.write(html);
            printWindow.document.close();

            // Wait for content to load, then trigger print dialog
            printWindow.onload = function() {
              setTimeout(() => {
                printWindow.print();
              }, 500);
            };
          })
          .catch(error => {
            console.error("Error loading guarantor form:", error);
            printWindow.close();
            alert("Failed to load guarantor form. Please try again.");
          });
        } else {
          alert("Please allow popups to generate the guarantor form.");
        }
      });
    }

    const selectedType = () => {
      const el = loanForm.querySelector('input[name="loan_type"]:checked');
      return el ? types.find((t) => t.key === el.value) : null;
    };
    const num = (el) => parseFloat((el && el.value ? el.value : "").replace(/,/g, "")) || 0;

    const update = () => {
      const type = selectedType();
      const amount = num(amountInput);
      if (preview) {
        if (!type || amount <= 0) {
          preview.innerHTML = '<p class="text-ink-400 text-sm">Choose a loan type and enter the amount to see what you will repay.</p>';
        } else {
          const interest = Math.round(amount * type.rate) / 100;
          const total = amount + interest;
          const due = new Date();
          due.setDate(due.getDate() + type.days);
          preview.innerHTML =
            `<div class="kv"><dt>Interest (${type.rate}%)</dt><dd class="font-mono">GHS ${money(interest)}</dd></div>` +
            `<div class="kv"><dt>You repay in total</dt><dd class="font-mono text-navy-800 font-semibold">GHS ${money(total)}</dd></div>` +
            `<div class="kv"><dt>Time to repay</dt><dd>${type.days} days</dd></div>` +
            `<div class="kv"><dt>Due about</dt><dd>${due.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}</dd></div>` +
            `<p class="text-[11px] text-ink-400 mt-2">The exact due date counts from the day the loan is approved.</p>`;
        }
      }
      if (second) {
        const isGuest = loanForm.classList.contains("guest-loan");
        // Second guarantor is always required for all loans
        const needed = true;
        second.classList.toggle("hidden", !needed);
        second.querySelectorAll("input").forEach((i) => {
          // For guest loans, UCU number is optional for second guarantor
          if (isGuest && i.name === "g2_ucu_number") {
            i.required = false;
          } else {
            i.required = needed;
          }
        });
        if (secondNote) {
          secondNote.textContent = isGuest
            ? "Non-member loans require a second guarantor who is your close friend or family member (UCU membership not required)."
            : "All loans require a second guarantor who is a UCU member.";
        }
      }
    };
    typeInputs.forEach((i) => i.addEventListener("change", update));
    if (amountInput) amountInput.addEventListener("input", update);
    if (earningsInput) earningsInput.addEventListener("input", update);
    update();

    // Check that a UCU number exists (shows a hidden version of the name)
    loanForm.querySelectorAll("[data-ucu-check]").forEach((input) => {
      const out = loanForm.querySelector(input.dataset.ucuCheck);
      let timer;
      const run = () => {
        const value = input.value.trim();
        if (!out) return;
        if (value.length < 6) { out.textContent = ""; return; }
        fetch("/api/guarantor?ucu=" + encodeURIComponent(value))
          .then((r) => r.json())
          .then((d) => {
            if (d.found) {
              out.textContent = "UCU member found: " + d.name;
              out.className = "hint text-green-700";
            } else {
              out.textContent = d.error || "No active member with this UCU number.";
              out.className = "hint text-red-700";
            }
          })
          .catch(() => {});
      };
      input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 500); });
      if (input.value) run();
    });
  }

  // ---- Live clock on dashboards ----
  const clock = document.getElementById("live-datetime");
  if (clock) {
    const tick = () => {
      const now = new Date();
      clock.textContent = now.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric" }) +
        " • " + now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    };
    tick();
    setInterval(tick, 30000);
  }
});


// ---------------------------------------------------------------------------
// Motion: scroll reveal, number count-up, header shadow
// ---------------------------------------------------------------------------
(function () {
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const ready = (fn) => (document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", fn) : fn());

  ready(() => {
    // Stagger the children of any element marked data-stagger (each one a little later).
    document.querySelectorAll("[data-stagger]").forEach((parent) => {
      const step = parseInt(parent.dataset.stagger, 10) || 90;
      Array.from(parent.children).forEach((child, i) => {
        child.classList.add("reveal");
        child.style.setProperty("--d", i * step + "ms");
      });
    });

    // Reveal elements as they scroll into view.
    const targets = document.querySelectorAll(".reveal");
    if (reduce || !("IntersectionObserver" in window)) {
      targets.forEach((el) => el.classList.add("in"));
    } else {
      const io = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("in");
            io.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
      targets.forEach((el) => io.observe(el));
    }

    // Count up numbers such as 97, 1,175.00 or GHS 2,500.00 when they appear.
    const pattern = /^(GHS\s+)?(\d[\d,]*)(\.\d+)?(\+|%)?$/;
    const counters = [];
    document.querySelectorAll("[data-count], .stat-value").forEach((el) => {
      const text = el.textContent.trim();
      const m = pattern.exec(text);
      if (m && !el.dataset.counted) counters.push({ el, prefix: m[1] || "", value: parseFloat((m[2] + (m[3] || "")).replace(/,/g, "")),
        decimals: m[3] ? m[3].length - 1 : 0, suffix: m[4] || "", original: text });
    });
    const run = ({ el, prefix, value, decimals, suffix, original }) => {
      el.dataset.counted = "1";
      if (reduce || value === 0) return;
      const start = performance.now(), duration = 1400;
      const fmt = (n) => prefix + n.toLocaleString("en-GH", { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
      const tick = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 4);
        el.textContent = t < 1 ? fmt(value * eased) : original;
        if (t < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    };
    if ("IntersectionObserver" in window && !reduce) {
      const co = new IntersectionObserver((entries) => {
        entries.forEach((e) => { if (e.isIntersecting) { const c = counters.find((x) => x.el === e.target); if (c) run(c); co.unobserve(e.target); } });
      }, { threshold: 0.4 });
      counters.forEach((c) => co.observe(c.el));
    }

    // Tall photos (such as phone screenshots) are shown whole instead of cropped.
    document.querySelectorAll(".g-item img").forEach((img) => {
      const mark = () => { if (img.naturalHeight > img.naturalWidth * 1.1) img.classList.add("is-portrait"); };
      img.complete ? mark() : img.addEventListener("load", mark);
    });

    // Header gets a soft shadow once the page is scrolled.
    const header = document.getElementById("site-header");
    if (header) {
      const onScroll = () => header.classList.toggle("scrolled", window.scrollY > 8);
      onScroll();
      window.addEventListener("scroll", onScroll, { passive: true });
    }
  });
})();


// Gallery lightbox (used with Alpine: x-data="galleryLightbox(items)")
window.galleryLightbox = function (items) {
  return {
    items, open: false, i: 0, touchX: null,
    show(index) { this.i = index; this.open = true; document.body.classList.add("overflow-hidden"); },
    close() { this.open = false; document.body.classList.remove("overflow-hidden"); },
    next() { this.i = (this.i + 1) % this.items.length; },
    prev() { this.i = (this.i - 1 + this.items.length) % this.items.length; },
    start(e) { this.touchX = e.changedTouches[0].clientX; },
    end(e) {
      if (this.touchX === null) return;
      const dx = e.changedTouches[0].clientX - this.touchX;
      if (Math.abs(dx) > 50) dx < 0 ? this.next() : this.prev();
      this.touchX = null;
    },
    get current() { return this.items[this.i] || {}; },
  };
};


// Home page carousel (used with Alpine: x-data="heroCarousel(count, milliseconds)")
window.heroCarousel = function (count, interval) {
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  return {
    i: 0, count, interval: interval || 6500, paused: false, timer: null, deadline: 0, remaining: interval || 6500, touchX: null,
    init() {
      if (this.count < 2 || reduce) return;
      this.schedule(this.interval);
      document.addEventListener("visibilitychange", () => (document.hidden ? this.hold() : this.release()));
    },
    schedule(ms) {
      clearTimeout(this.timer);
      this.remaining = ms;
      this.deadline = Date.now() + ms;
      this.timer = setTimeout(() => this.next(), ms);
    },
    go(n) {
      this.i = (n + this.count) % this.count;
      if (this.count > 1 && !reduce) { this.paused ? (this.remaining = this.interval) : this.schedule(this.interval); }
    },
    next() { this.go(this.i + 1); },
    prev() { this.go(this.i - 1); },
    hold() { if (this.paused) return; this.paused = true; clearTimeout(this.timer); this.remaining = Math.max(300, this.deadline - Date.now()); },
    release() { if (!this.paused || reduce || this.count < 2) { this.paused = false; return; } this.paused = false; this.schedule(this.remaining); },
    toggle() { this.paused ? this.release() : this.hold(); },
    start(e) { this.touchX = e.changedTouches[0].clientX; },
    end(e) {
      if (this.touchX === null) return;
      const dx = e.changedTouches[0].clientX - this.touchX;
      if (Math.abs(dx) > 45) dx < 0 ? this.next() : this.prev();
      this.touchX = null;
    },
  };
};
