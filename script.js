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

// Hero video: slow on mobile + crossfade loop
if (heroBg) {
  if (window.innerWidth <= 768) {
    heroBg.playbackRate = 0.45;
  }

}

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

  // Modal trigger: 60% scroll
  if (!modalTriggered && docHeight > 0 && (scrollY / docHeight) >= 0.6) {
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
    setTimeout(function() { showModal(); }, 30000);
  }
}

