// Elements
const navbar = document.getElementById('navbar');
const navToggle = document.getElementById('navToggle');
const navLinks = document.getElementById('navLinks');
const backToTop = document.getElementById('backToTop');
const sections = document.querySelectorAll('section[id]');
const navLinkElements = document.querySelectorAll('.nav-links a');
const heroBg = document.querySelector('.hero-bg');
const readingProgress = document.getElementById('readingProgress');
const stickyCta = document.querySelector('.sticky-cta');

// Detect guide pages (have reading progress bar)
const isGuidePage = !!readingProgress;

// Single scroll handler for all scroll-based effects
function onScroll() {
  const scrollY = window.scrollY;
  const docHeight = document.documentElement.scrollHeight - window.innerHeight;

  // Navbar shadow
  if (navbar) {
    navbar.classList.toggle('scrolled', scrollY > 50);
  }

  // Back to top button
  if (backToTop) {
    backToTop.classList.toggle('visible', scrollY > 600);
  }

  // Active nav link highlighting (homepage only — sections exist)
  if (sections.length > 0 && navLinkElements.length > 0) {
    let currentSection = '';
    sections.forEach(function(section) {
      if (section.offsetTop <= scrollY + 120) {
        currentSection = section.getAttribute('id');
      }
    });
    navLinkElements.forEach(function(link) {
      link.classList.remove('active');
      if (link.getAttribute('href') === '#' + currentSection) {
        link.classList.add('active');
      }
    });
  }


  // Reading progress bar (guide pages)
  if (readingProgress && docHeight > 0) {
    var pct = Math.min((scrollY / docHeight) * 100, 100);
    readingProgress.style.width = pct + '%';
  }

  // Sticky CTA (guide pages) — show after 400px, hide near footer
  if (stickyCta) {
    var footer = document.querySelector('.footer');
    var nearFooter = false;
    if (footer) {
      nearFooter = scrollY + window.innerHeight >= footer.offsetTop;
    }
    if (scrollY > 400 && !nearFooter) {
      stickyCta.classList.add('visible');
    } else {
      stickyCta.classList.remove('visible');
    }
  }

  // Modal trigger: 40% scroll
  if (!modalTriggered && docHeight > 0 && (scrollY / docHeight) >= 0.4) {
    showModal();
  }
}

window.addEventListener('scroll', onScroll);
onScroll();

// Mobile nav toggle
if (navToggle && navLinks) {
  navToggle.addEventListener('click', function() {
    navLinks.classList.toggle('active');
  });

  navLinks.querySelectorAll('a').forEach(function(link) {
    link.addEventListener('click', function() {
      navLinks.classList.remove('active');
    });
  });
}

// Back to top click
if (backToTop) {
  backToTop.addEventListener('click', function() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

// Copy link button
var copyLink = document.getElementById('copyLink');
if (copyLink) {
  copyLink.addEventListener('click', function() {
    navigator.clipboard.writeText(window.location.href).then(function() {
      var msg = document.getElementById('shareMsg');
      if (msg) {
        msg.textContent = 'Link copied!';
        setTimeout(function() { msg.textContent = ''; }, 3000);
      }
    });
  });
}

// --- Scroll-triggered fade-in animations (IntersectionObserver) ---
(function() {
  // Selectors for elements to animate
  var targets = document.querySelectorAll(
    '.card, .feature-card, .college-card, .event-card, .guide-card, .rental-card, ' +
    '.family-item, .stat-card, .section-header, .section-photo, .info-banner, ' +
    '.welcome-text, .welcome-stats, .shop-card, .pro-tip'
  );

  if (!targets.length || !('IntersectionObserver' in window)) return;

  // Check reduced motion
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) return;

  // Apply initial classes
  targets.forEach(function(el, i) {
    // Section photos get fade-in-left, headers get fade-in, everything else fade-in-up
    if (el.classList.contains('section-photo')) {
      el.classList.add('fade-in-left');
    } else if (el.classList.contains('section-header')) {
      el.classList.add('fade-in');
    } else {
      el.classList.add('fade-in-up');
    }

    // Stagger cards within grid parents
    var parent = el.parentElement;
    if (parent && (parent.classList.contains('card-grid') ||
        parent.classList.contains('college-grid') ||
        parent.classList.contains('events-grid') ||
        parent.classList.contains('guides-grid') ||
        parent.classList.contains('feature-grid') ||
        parent.classList.contains('family-grid') ||
        parent.classList.contains('rentals-grid') ||
        parent.classList.contains('welcome-stats'))) {
      var siblings = Array.from(parent.children);
      var idx = siblings.indexOf(el);
      el.style.transitionDelay = (idx * 0.08) + 's';
    }
  });

  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  targets.forEach(function(el) { observer.observe(el); });
})();

// --- Email/Phone Signup Modal ---
var modalTriggered = false;
var modalOverlay = document.getElementById('signupModal');

function shouldShowModal() {
  if (!modalOverlay) return false;
  if (localStorage.getItem('ilc_modal_dismissed')) return false;
  if (sessionStorage.getItem('ilc_modal_shown')) return false;
  return true;
}

function showModal() {
  if (modalTriggered || !shouldShowModal()) return;
  modalTriggered = true;
  sessionStorage.setItem('ilc_modal_shown', '1');
  modalOverlay.classList.add('active');
}

function hideModal() {
  if (!modalOverlay) return;
  modalOverlay.classList.remove('active');
  localStorage.setItem('ilc_modal_dismissed', '1');
}

// Modal event listeners
if (modalOverlay) {
  // Close button
  var closeBtn = modalOverlay.querySelector('.modal-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', hideModal);
  }

  // Click overlay
  modalOverlay.addEventListener('click', function(e) {
    if (e.target === modalOverlay) hideModal();
  });

  // Escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && modalOverlay.classList.contains('active')) {
      hideModal();
    }
  });

  // Timer trigger: 10 seconds
  if (shouldShowModal()) {
    setTimeout(function() { showModal(); }, 10000);
  }
}

// --- Image lazy-load fade-in ---
(function() {
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) return;

  var images = document.querySelectorAll('.section-photo img, .article-body img');
  images.forEach(function(img) {
    if (img.complete && img.naturalHeight > 0) {
      // Already loaded (cached)
      return;
    }
    img.classList.add('img-lazy');
    img.addEventListener('load', function() {
      img.classList.remove('img-lazy');
      img.classList.add('img-loaded');
    });
  });
})();
