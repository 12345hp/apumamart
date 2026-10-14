// ApumaMart Nav Fix — CFT + Home + Back button (bulletproof)
// 1. Injects 📦 CFT Calculator into top nav (keeps watching for SPA changes)
// 2. Injects 🏠 Home button for easy return to workspace
// 3. Fixes back-button: ensures history entry so back goes to workspace
// 4. Registers offline service worker (app works without internet after install)
(function(){
  // ---- Offline Service Worker ----
  if ('serviceWorker' in navigator){
    window.addEventListener('load', function(){
      navigator.serviceWorker.register('/sw.js').catch(function(){});
    });
  }
  // ---- Capture real auth token from app's API calls ----
  // The React app sends Authorization: Bearer <token> on API calls.
  // We save it so branches.html can use the correct token.
  try {
    var _origFetch = window.fetch;
    window.fetch = function(url, opts){
      try {
        var h = (opts && opts.headers) || {};
        var auth = h['Authorization'] || h['authorization'];
        if (auth && /^Bearer\s+/i.test(auth)){
          var t = auth.replace(/^Bearer\s+/i,'').trim();
          if (t.length > 10){
            try { localStorage.setItem('am_branch_token', t); } catch(e){}
          }
        }
      } catch(e){}
      return _origFetch.apply(this, arguments);
    };
  } catch(e){}
  var CFT_URL = '/cft-calculator.html';
  var HOME_URL = '/';
  var SUB_URL = '/subscribe.html';
  var CFT_ID = 'am-cft-nav-btn';
  var HOME_ID = 'am-home-nav-btn';
  var SUB_ID = 'am-sub-nav-btn';

  function norm(s){ return (s||'').toLowerCase().replace(/\s+/g,' ').trim(); }

  function isVisible(el){
    if (!el) return false;
    var r = el.getBoundingClientRect();
    return r.width > 20 && r.height > 10;
  }

  function makeBtn(id, label, url, bg){
    var b = document.createElement('button');
    b.id = id; b.type = 'button'; b.innerHTML = label;
    b.style.cssText = 'background:'+bg+';color:#fff;border:none;border-radius:10px;'
      + 'padding:10px 18px;margin:0 6px;font-size:14px;font-weight:700;'
      + 'cursor:pointer;white-space:nowrap;box-shadow:0 2px 6px rgba(0,0,0,.15);'
      + 'flex-shrink:0;';
    b.onclick = function(e){
      e.preventDefault(); e.stopPropagation();
      window.location.href = url;
    };
    return b;
  }

  // Find any visible element containing the keyword, return its clickable ancestor
  function findClickable(keyword){
    var all = document.getElementsByTagName('*');
    for (var i=0;i<all.length;i++){
      var el = all[i];
      if (el.id===CFT_ID||el.id===HOME_ID||el.id===SUB_ID) continue;
      var t = norm(el.innerText);
      if (!t || t.length > 50 || t.indexOf(keyword) < 0) continue;
      if (!isVisible(el)) continue;
      // Climb to clickable parent
      var c = el, d = 0;
      while (c && d < 6){
        var tag = (c.tagName||'').toLowerCase();
        if (tag==='button'||tag==='a'||c.getAttribute('role')==='button') return c;
        c = c.parentElement; d++;
      }
      return el;
    }
    return null;
  }

  function ensureBtn(id, label, url, bg, anchorKeyword){
    if (document.getElementById(id)) return true;
    var anchor = findClickable(anchorKeyword);
    if (!anchor || !anchor.parentElement) return false;
    var btn = makeBtn(id, label, url, bg);
    var p = anchor.parentElement;
    // For CFT: insert right after the anchor. For Home: insert before first nav item.
    if (id === HOME_ID){
      p.insertBefore(btn, p.firstChild);
    } else if (anchor.nextSibling){
      p.insertBefore(btn, anchor.nextSibling);
    } else {
      p.appendChild(btn);
    }
    return true;
  }

  // Route "Multiple Branches" clicks to the branch management page
  function hookBranches(){
    if (hookBranches._done) return;
    var el = findClickable('branch');
    if (!el) return;
    // Find the actual clickable (button/card)
    var c = el, d = 0;
    while (c && d < 8){
      var tag = (c.tagName||'').toLowerCase();
      if (tag==='button'||tag==='a'||c.getAttribute('role')==='button'||c.onclick){ break; }
      // Also treat clickable-looking divs (cards) as targets
      var cs = '';
      try{ cs = window.getComputedStyle(c).cursor; }catch(e){}
      if (cs === 'pointer' && d > 0) break;
      c = c.parentElement; d++;
    }
    if (!c) return;
    // Avoid double-hooking
    if (c.getAttribute('data-am-branch-hooked')) return;
    c.setAttribute('data-am-branch-hooked', '1');
    c.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      window.location.href = '/branches.html';
    }, true);
    hookBranches._done = true;
  }

  // V6 WARRANTY v2: Bulletproof redirect using document-level capture.
  // Catches clicks on the 5 broken buttons BEFORE React handles them,
  // no matter when/how the buttons are rendered.
  var BROKEN_REDIRECTS = {
    'suppliers': '/suppliers.html',
    'expenses': '/expenses.html',
    'gift cards': '/giftcards.html',
    'online orders': '/online-orders.html',
    'recurring bills': '/recurring-bills.html'
  };
  function hookBrokenBusinessButtons(){
    if (hookBrokenBusinessButtons._done) return;
    hookBrokenBusinessButtons._done = true;
    document.addEventListener('click', function(e){
      try {
        var el = e.target;
        // Walk up max 6 levels to find button-like element with matching text
        for (var d = 0; d < 6 && el && el !== document; d++){
          var txt = (el.innerText || el.textContent || '').toLowerCase().trim();
          // Only match if we're inside Business tools view (avoid false positives)
          for (var label in BROKEN_REDIRECTS){
            if (txt === label || (txt.length < 30 && txt.indexOf(label) !== -1)){
              // Double-check: is this inside a business tools context?
              var p = el, inBusiness = false;
              for (var q = 0; q < 10 && p && p !== document; q++){
                var pt = (p.innerText || '').toLowerCase();
                if (pt.indexOf('business tools') !== -1){ inBusiness = true; break; }
                p = p.parentElement;
              }
              if (inBusiness || txt === label){
                e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
                window.location.href = BROKEN_REDIRECTS[label];
                return false;
              }
            }
          }
          el = el.parentElement;
        }
      } catch(err){}
    }, true); // capture=true: runs BEFORE React's handlers
  }

  function injectAll(){
    // Route Multiple Branches → branch management page
    hookBranches();
    // V6 WARRANTY: Route 5 broken Business buttons → standalone fixed pages
    hookBrokenBusinessButtons();
    // CFT near Branches
    ensureBtn(CFT_ID, '📦 CFT Calculator', CFT_URL,
      'linear-gradient(135deg,#2e7d32,#43a047)', 'branch');
    // Home at start of nav (near Modern Billing) — symbol only, like every app
    ensureBtn(HOME_ID, '🏠', HOME_URL,
      'linear-gradient(135deg,#1565C0,#1E88E5)', 'modern billing');
    // Subscribe near Help & Support
    var helpEl = findClickable('help');
    if (helpEl && !document.getElementById(SUB_ID) && helpEl.parentElement){
      var sb = makeBtn(SUB_ID, '👑 Subscribe', SUB_URL,
        'linear-gradient(135deg,#FF9800,#FF5722)');
      var hp = helpEl.parentElement;
      // climb to clickable if needed
      var hc = helpEl, hd = 0;
      while (hc && hd < 6){
        var ht = (hc.tagName||'').toLowerCase();
        if (ht==='button'||ht==='a') break;
        hc = hc.parentElement; hd++;
      }
      if (hc && hc.parentElement){
        if (hc.nextSibling) hc.parentElement.insertBefore(sb, hc.nextSibling);
        else hc.parentElement.appendChild(sb);
      }
    }
  }

  // ---- Back-button fix ----
  // When app navigates to billing view via SPA, ensure a history entry exists
  // so the browser back button returns to workspace instead of newtab.
  var lastUrl = location.href;
  function fixHistory(){
    // If we're on the main app (not workspace cards page) and history is thin,
    // push a workspace entry so back has somewhere to go.
    try{
      var isWorkspace = document.body.innerText.indexOf('Choose your workspace') >= 0;
      if (!isWorkspace && window.history.length <= 1){
        window.history.replaceState({am:'workspace'}, '', HOME_URL);
        window.history.pushState({am:'billing'}, '', location.href);
      }
    }catch(e){}
  }

  // Keep watching forever (SPA route changes)
  var obs = new MutationObserver(function(){ injectAll(); fixHistory(); });
  try{ obs.observe(document.documentElement,{childList:true,subtree:true}); }catch(e){}

  var timer = setInterval(function(){ injectAll(); fixHistory(); }, 800);
  // Stop aggressive polling after 60s, but keep observer
  setTimeout(function(){ clearInterval(timer); }, 60000);

  injectAll();
  setTimeout(injectAll, 1500);
  setTimeout(fixHistory, 2000);

  // Handle back button: if user goes back to our pushed state, go to workspace
  window.addEventListener('popstate', function(e){
    if (e.state && e.state.am === 'workspace'){
      window.location.href = HOME_URL;
    }
  });
})();
