'use strict';

    // ---------------------------------------------------------------------
    // Popup vs. full-tab mode
    // ---------------------------------------------------------------------
    const IS_TAB = new URLSearchParams(location.search).get('tab') === '1';
    document.documentElement.classList.add(IS_TAB ? 'is-tab' : 'is-popup');

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------
    const DB_NAME = 'FortifyGenVaultDB';
    const DB_VERSION = 1;
    const TARGET_ITERATIONS = 600000;     // PBKDF2-SHA256 (OWASP guidance)
    const LEGACY_ITERATIONS = 100000;     // vaults created before iterations were stored
    const MIN_PASSPHRASE_LEN = 12;
    const CHECK_VALUE = 'FORTIFY_VALID';
    const IDLE_LOCK_MS = 5 * 60 * 1000;
    const HIDDEN_LOCK_MS = 60 * 1000;
    const CLIPBOARD_CLEAR_MS = 30 * 1000;
    const MAX_IMPORT_BYTES = 20 * 1024 * 1024;

    let dbInstance = null;
    let dbError = null;
    let masterCryptoKey = null;
    let vaultItems = [];
    let saveChain = Promise.resolve();
    const revealedIds = new Set();

    const $ = (id) => document.getElementById(id);

    // ---------------------------------------------------------------------
    // Crypto helpers (PBKDF2 -> AES-256-GCM)
    // ---------------------------------------------------------------------
    async function deriveKey(masterPassword, saltBytes, iterations) {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(masterPassword), { name: 'PBKDF2' }, false, ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }

    async function encryptText(text, key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, new TextEncoder().encode(text)
      );
      return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(encrypted)) };
    }

    async function decryptText(obj, key) {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(obj.iv) }, key, new Uint8Array(obj.ciphertext)
      );
      return new TextDecoder().decode(decrypted);
    }

    // ---------------------------------------------------------------------
    // IndexedDB (errors are rejected, never confused with "not found")
    // ---------------------------------------------------------------------
    function initDB() {
      return new Promise((resolve, reject) => {
        if (!window.indexedDB) { reject(new Error('IndexedDB is not available in this browser or mode.')); return; }
        let request;
        try { request = indexedDB.open(DB_NAME, DB_VERSION); } catch (e) { reject(e); return; }
        request.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('vaultStore')) {
            db.createObjectStore('vaultStore', { keyPath: 'id' });
          }
        };
        request.onsuccess = (e) => { dbInstance = e.target.result; resolve(dbInstance); };
        request.onerror = () => reject(request.error || new Error('Could not open database.'));
        request.onblocked = () => reject(new Error('Database is blocked by another tab. Close other FortifyGen tabs and reload.'));
      });
    }

    const dbReady = initDB().catch((e) => { dbError = e; return null; });

    function dbGet(key) {
      return new Promise((resolve, reject) => {
        if (!dbInstance) { reject(new Error('Database not ready.')); return; }
        try {
          const req = dbInstance.transaction('vaultStore', 'readonly').objectStore('vaultStore').get(key);
          req.onsuccess = () => resolve(req.result === undefined ? null : req.result);
          req.onerror = () => reject(req.error);
        } catch (e) { reject(e); }
      });
    }

    // Writes all items in ONE transaction: either everything is stored or nothing is.
    function dbPutMany(items) {
      return new Promise((resolve, reject) => {
        if (!dbInstance) { reject(new Error('Database not ready.')); return; }
        try {
          const tx = dbInstance.transaction('vaultStore', 'readwrite');
          const store = tx.objectStore('vaultStore');
          items.forEach((item) => store.put(item));
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error || new Error('Write aborted.'));
        } catch (e) { reject(e); }
      });
    }

    const dbPut = (item) => dbPutMany([item]);

    // ---------------------------------------------------------------------
    // Multi-tab coordination
    // ---------------------------------------------------------------------
    const channel = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('fortifygen-vault') : null;
    function notifyOtherTabs(type) { try { if (channel) channel.postMessage({ type }); } catch (e) { /* ignore */ } }

    if (channel) {
      channel.onmessage = async (ev) => {
        if (!masterCryptoKey) return;
        const type = ev.data && ev.data.type;
        if (type === 'meta') {
          lockVault('Vault changed in another tab. Locked.');
        } else if (type === 'data') {
          try { await loadVaultItems(); renderVaultList(); }
          catch (e) { lockVault('Could not refresh vault. Locked for safety.'); }
        }
      };
    }

    // ---------------------------------------------------------------------
    // Generator
    // ---------------------------------------------------------------------
    const charSets = {
      upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lower: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      symbols: '!@#$%^&*-_=+?.,:;'
    };
    const AMBIGUOUS = 'Il1O0o|';

    const lengthSlider = $('length-slider');
    const lengthVal = $('length-val');
    const chkUpper = $('chk-upper');
    const chkLower = $('chk-lower');
    const chkNumbers = $('chk-numbers');
    const chkSymbols = $('chk-symbols');
    const chkAmbiguous = $('chk-ambiguous');
    const generateBtn = $('generate-btn');
    const passwordDisplay = $('password-display');
    const copyBtn = $('copy-btn');
    const toggleVisibilityBtn = $('toggle-visibility-btn');
    const visibilityText = $('visibility-text');
    const strengthBar = $('strength-bar');
    const strengthText = $('strength-text');
    const themeToggle = $('theme-toggle');

    let currentPassword = '';
    let isMasked = false;

    lengthSlider.addEventListener('input', (e) => { lengthVal.textContent = e.target.value; });

    // Unbiased random integer in [0, max) via rejection sampling.
    function randInt(max) {
      const limit = Math.floor(0x100000000 / max) * max;
      const buf = new Uint32Array(1);
      do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
      return buf[0] % max;
    }

    function randomChar(str) { return str[randInt(str.length)]; }

    function shuffleArray(arr) {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = randInt(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      return arr;
    }

    function activeSets() {
      const sets = [];
      if (chkUpper.checked) sets.push(charSets.upper);
      if (chkLower.checked) sets.push(charSets.lower);
      if (chkNumbers.checked) sets.push(charSets.numbers);
      if (chkSymbols.checked) sets.push(charSets.symbols);
      if (!chkAmbiguous.checked) return sets;
      return sets.map((s) => Array.from(s).filter((c) => !AMBIGUOUS.includes(c)).join(''));
    }

    // Keep at least one character class selected (the last checked box can't be unchecked).
    [chkUpper, chkLower, chkNumbers, chkSymbols].forEach((chk) => {
      chk.addEventListener('change', () => {
        if (![chkUpper, chkLower, chkNumbers, chkSymbols].some((c) => c.checked)) {
          chk.checked = true;
          showToast('At least one character type is required.');
        }
      });
    });

    function generatePassword() {
      const length = parseInt(lengthSlider.value, 10);
      const sets = activeSets();
      const pool = sets.join('');

      const chars = sets.map(randomChar); // guarantee one of each selected type
      while (chars.length < length) chars.push(randomChar(pool));

      currentPassword = shuffleArray(chars).join('');
      updatePasswordDisplay();
      updateStrengthIndicator(length * Math.log2(pool.length));
    }

    function updatePasswordDisplay() {
      if (!currentPassword) { passwordDisplay.textContent = 'Click Generate'; return; }
      passwordDisplay.textContent = isMasked ? '•'.repeat(currentPassword.length) : currentPassword;
      passwordDisplay.classList.remove('text-muted');
    }

    // Based on entropy (length x log2(pool size)), not on how many boxes are ticked.
    function updateStrengthIndicator(bits) {
      let label = 'Weak', barClass = 'strength-weak', color = '#ef4444';
      if (bits >= 90) { label = 'Strong'; barClass = 'strength-strong'; color = '#4ade80'; }
      else if (bits >= 60) { label = 'Medium'; barClass = 'strength-medium'; color = '#facc15'; }
      strengthText.textContent = `${label} · ${Math.round(bits)} bits`;
      strengthText.style.color = color;
      strengthBar.className = `strength-bar-fill ${barClass}`;
    }

    // ---------------------------------------------------------------------
    // UI helpers: toast, clipboard, modals
    // ---------------------------------------------------------------------
    let toastTimer = null;
    function showToast(msg) {
      const t = $('toast-msg');
      t.textContent = msg;
      t.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
    }

    function legacyCopy(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;';
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    }

    let clipboardTimer = null;
    async function copyToClipboard(text) {
      if (!text) return;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
          ok = true;
        }
      } catch (e) { ok = false; }
      if (!ok) ok = legacyCopy(text);

      if (!ok) { showToast('Copy failed. Select and copy manually.'); return; }
      showToast('Copied!');

      clearTimeout(clipboardTimer);
      clipboardTimer = setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === text) await navigator.clipboard.writeText('');
        } catch (e) { /* no permission or no focus: leave clipboard alone */ }
      }, CLIPBOARD_CLEAR_MS);
    }

    // Modal handling: focus management, Escape to close, Tab trap.
    let activeModal = null;
    let lastFocused = null;
    const modalCancel = new Map();

    function openModal(el, focusId, onCancel) {
      lastFocused = document.activeElement;
      activeModal = el;
      modalCancel.set(el, onCancel || (() => closeModal(el)));
      el.classList.add('active');
      const target = focusId ? $(focusId) : el.querySelector('input, button');
      if (target) setTimeout(() => target.focus(), 30);
    }

    function closeModal(el) {
      el.classList.remove('active');
      if (activeModal === el) {
        activeModal = null;
        if (lastFocused && document.contains(lastFocused)) { try { lastFocused.focus(); } catch (e) { /* ignore */ } }
      }
    }

    document.addEventListener('keydown', (e) => {
      if (!activeModal) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        const fn = modalCancel.get(activeModal);
        if (fn) fn(); else closeModal(activeModal);
      } else if (e.key === 'Tab') {
        const focusables = activeModal.querySelectorAll('input, button, [tabindex]:not([tabindex="-1"])');
        if (!focusables.length) return;
        const first = focusables[0], last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });

    function confirmDialog(message, okLabel) {
      return new Promise((resolve) => {
        const modal = $('modal-confirm');
        $('confirm-message').textContent = message;
        $('confirm-ok-btn').textContent = okLabel || 'Confirm';
        const finish = (val) => {
          $('confirm-ok-btn').onclick = null;
          $('confirm-cancel-btn').onclick = null;
          closeModal(modal);
          resolve(val);
        };
        $('confirm-ok-btn').onclick = () => finish(true);
        $('confirm-cancel-btn').onclick = () => finish(false);
        openModal(modal, 'confirm-cancel-btn', () => finish(false));
      });
    }

    // ---------------------------------------------------------------------
    // Tabs
    // ---------------------------------------------------------------------
    const tabGen = $('tab-btn-gen');
    const tabVault = $('tab-btn-vault');
    const secGen = $('sec-generator');
    const secVault = $('sec-vault');

    function showTab(name) {
      const gen = name === 'gen';
      tabGen.classList.toggle('active', gen);
      tabVault.classList.toggle('active', !gen);
      tabGen.setAttribute('aria-selected', String(gen));
      tabVault.setAttribute('aria-selected', String(!gen));
      secGen.style.display = gen ? 'flex' : 'none';
      secVault.style.display = gen ? 'none' : 'flex';
    }

    tabGen.addEventListener('click', () => showTab('gen'));
    tabVault.addEventListener('click', () => { showTab('vault'); checkVaultState(); });

    // ---------------------------------------------------------------------
    // Vault: state, unlock, create, lock
    // ---------------------------------------------------------------------
    function setAuthError(msg) { $('vault-auth-error').textContent = msg || ''; }

    async function checkVaultState() {
      if (masterCryptoKey) return;
      const authTitle = $('vault-auth-title');
      const authDesc = $('vault-auth-desc');
      const confirmGroup = $('confirm-pin-group');
      const unlockBtn = $('unlock-vault-btn');
      const pinInput = $('vault-pin-input');

      setAuthError('');
      await dbReady;

      if (!dbInstance) {
        authTitle.textContent = 'Storage unavailable';
        authDesc.textContent = 'The vault cannot open its local database, so it is disabled to avoid overwriting existing data.';
        setAuthError(dbError ? dbError.message : 'Database unavailable.');
        confirmGroup.style.display = 'none';
        unlockBtn.disabled = true;
        pinInput.disabled = true;
        return;
      }

      let meta;
      try { meta = await dbGet('meta'); }
      catch (e) {
        authTitle.textContent = 'Storage error';
        authDesc.textContent = 'Could not read the vault. Nothing has been changed.';
        setAuthError(e && e.message ? e.message : 'Read failed.');
        confirmGroup.style.display = 'none';
        unlockBtn.disabled = true;
        pinInput.disabled = true;
        return;
      }

      unlockBtn.disabled = false;
      pinInput.disabled = false;

      if (!meta) {
        authTitle.textContent = 'Setup New Vault';
        authDesc.textContent = 'Create a master passphrase to lock and protect your saved passwords.';
        confirmGroup.style.display = 'flex';
        pinInput.autocomplete = 'new-password';
        unlockBtn.textContent = 'Create Master Vault';
      } else {
        authTitle.textContent = 'Vault Locked';
        authDesc.textContent = 'Enter your master passphrase to unlock your encrypted local vault.';
        confirmGroup.style.display = 'none';
        pinInput.autocomplete = 'current-password';
        unlockBtn.textContent = 'Unlock Vault';
      }
    }

    async function verifyPassphrase(pin, meta) {
      const iterations = meta.iterations || LEGACY_ITERATIONS;
      const derived = await deriveKey(pin, new Uint8Array(meta.salt), iterations);
      try {
        const test = await decryptText(meta.checkToken, derived);
        return test === CHECK_VALUE ? derived : null;
      } catch (e) { return null; }
    }

    // Re-encrypt everything under a new key (new salt, current iteration count) in one transaction.
    async function rekey(newPin) {
      await saveChain.catch(() => {});
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(newPin, salt, TARGET_ITERATIONS);
      const checkToken = await encryptText(CHECK_VALUE, key);
      const encryptedData = await encryptText(JSON.stringify(vaultItems), key);
      await dbPutMany([
        { id: 'meta', salt: Array.from(salt), iterations: TARGET_ITERATIONS, checkToken },
        { id: 'data', encryptedData }
      ]);
      masterCryptoKey = key;
      notifyOtherTabs('meta');
    }

    function normalizeItems(items) {
      const seen = new Set();
      return items.map((it) => {
        let id = (it && it.id !== undefined && it.id !== null) ? String(it.id) : '';
        if (!id || seen.has(id)) id = newId();
        seen.add(id);
        return { id, service: String(it.service || ''), username: String(it.username || ''), password: String(it.password || '') };
      });
    }

    function newId() {
      if (crypto.randomUUID) return crypto.randomUUID();
      const b = crypto.getRandomValues(new Uint8Array(16));
      return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    }

    // Throws on failure. Never replaces data with an empty list.
    async function loadVaultItems() {
      const dataObj = await dbGet('data');
      if (!dataObj) { vaultItems = []; return; }
      const jsonStr = await decryptText(dataObj.encryptedData, masterCryptoKey);
      const parsed = JSON.parse(jsonStr);
      if (!Array.isArray(parsed)) throw new Error('Vault data is malformed.');
      vaultItems = normalizeItems(parsed);
    }

    function saveVaultItems() {
      const p = saveChain.catch(() => {}).then(async () => {
        if (!masterCryptoKey) return;
        const encryptedData = await encryptText(JSON.stringify(vaultItems), masterCryptoKey);
        await dbPut({ id: 'data', encryptedData });
        notifyOtherTabs('data');
      });
      saveChain = p;
      return p;
    }

    async function recoverAfterFailedSave() {
      try { await loadVaultItems(); } catch (e) { /* keep in-memory state */ }
      renderVaultList();
    }

    async function handleUnlock() {
      const pin = $('vault-pin-input').value;
      const confirmPin = $('vault-pin-confirm').value;
      const btn = $('unlock-vault-btn');
      setAuthError('');

      if (!pin) { setAuthError('Please enter a passphrase.'); return; }
      if (!dbInstance) { await checkVaultState(); return; }

      btn.disabled = true;
      const label = btn.textContent;
      btn.textContent = 'Working…';

      try {
        const meta = await dbGet('meta');

        if (!meta) {
          // Create new vault
          if (pin.length < MIN_PASSPHRASE_LEN) { setAuthError(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters.`); return; }
          if (pin !== confirmPin) { setAuthError('Passphrases do not match.'); return; }
          vaultItems = [];
          try { await rekey(pin); }
          catch (e) { masterCryptoKey = null; setAuthError('Could not create the vault: ' + (e && e.message ? e.message : 'write failed')); return; }
          requestPersistentStorage();
          showVaultMain();
          showToast('Vault created successfully!');
        } else {
          // Unlock existing vault
          const key = await verifyPassphrase(pin, meta);
          if (!key) { setAuthError('Incorrect passphrase.'); return; }

          masterCryptoKey = key;
          try { await loadVaultItems(); }
          catch (e) {
            masterCryptoKey = null;
            vaultItems = [];
            setAuthError('Passphrase accepted, but the vault data could not be decrypted. Nothing was changed. Try importing a backup.');
            return;
          }

          // Silently upgrade old vaults to the stronger key derivation.
          if ((meta.iterations || LEGACY_ITERATIONS) < TARGET_ITERATIONS) {
            try { await rekey(pin); } catch (e) { /* stay unlocked with the old key */ }
          }
          requestPersistentStorage();
          showVaultMain();
          showToast('Vault unlocked!');
        }
      } catch (e) {
        masterCryptoKey = null;
        setAuthError('Something went wrong: ' + (e && e.message ? e.message : 'unknown error'));
      } finally {
        btn.disabled = false;
        if (!masterCryptoKey) btn.textContent = label;
      }
    }

    $('unlock-form').addEventListener('submit', (e) => { e.preventDefault(); handleUnlock(); });

    function requestPersistentStorage() {
      try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch (e) { /* ignore */ }
    }

    function showVaultMain() {
      $('vault-auth-card').style.display = 'none';
      $('vault-main-card').style.display = 'flex';
      $('vault-pin-input').value = '';
      $('vault-pin-confirm').value = '';
      setAuthError('');
      renderVaultList();
      resetIdleTimer();
    }

    function lockVault(message) {
      masterCryptoKey = null;
      vaultItems = [];
      revealedIds.clear();
      clearTimeout(idleTimer);
      clearTimeout(hiddenTimer);

      // Remove every trace of vault content from the DOM.
      $('vault-items-container').textContent = '';
      $('vault-search').value = '';
      $('vault-count').textContent = '0';
      ['save-item-service', 'save-item-username', 'save-item-password',
       'pass-current', 'pass-new', 'pass-new-confirm', 'vault-pin-input', 'vault-pin-confirm'
      ].forEach((id) => { $(id).value = ''; });
      $('pass-error').textContent = '';

      ['modal-save', 'modal-pass', 'modal-confirm'].forEach((id) => {
        const fn = modalCancel.get($(id));
        if (id === 'modal-confirm' && $(id).classList.contains('active') && fn) fn();
        $(id).classList.remove('active');
      });
      activeModal = null;

      $('vault-auth-card').style.display = 'flex';
      $('vault-main-card').style.display = 'none';
      checkVaultState();
      if (message) showToast(message);
    }

    $('lock-vault-btn').addEventListener('click', () => lockVault('Vault locked.'));

    // ---------------------------------------------------------------------
    // Auto-lock (inactivity, and when the page stays hidden)
    // ---------------------------------------------------------------------
    let idleTimer = null;
    let hiddenTimer = null;

    function resetIdleTimer() {
      clearTimeout(idleTimer);
      if (!masterCryptoKey) return;
      idleTimer = setTimeout(() => lockVault('Locked after inactivity.'), IDLE_LOCK_MS);
    }
    ['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach((evt) => {
      window.addEventListener(evt, resetIdleTimer, { passive: true });
    });

    document.addEventListener('visibilitychange', () => {
      clearTimeout(hiddenTimer);
      if (document.hidden && masterCryptoKey) {
        hiddenTimer = setTimeout(() => lockVault('Locked while the app was in the background.'), HIDDEN_LOCK_MS);
      }
    });

    // ---------------------------------------------------------------------
    // Vault list (built with DOM APIs; passwords are not kept in the DOM until revealed)
    // ---------------------------------------------------------------------
    function h(tag, props, text) {
      const e = document.createElement(tag);
      if (props) Object.keys(props).forEach((k) => {
        if (k === 'class') e.className = props[k];
        else if (k === 'dataset') Object.keys(props[k]).forEach((d) => { e.dataset[d] = props[k][d]; });
        else e.setAttribute(k, props[k]);
      });
      if (text !== undefined) e.textContent = text;
      return e;
    }

    function renderVaultList() {
      const container = $('vault-items-container');
      const searchVal = $('vault-search').value.toLowerCase();
      $('vault-count').textContent = vaultItems.length;
      container.textContent = '';

      const filtered = vaultItems.filter((i) =>
        i.service.toLowerCase().includes(searchVal) || i.username.toLowerCase().includes(searchVal)
      );

      if (filtered.length === 0) {
        container.appendChild(h('div', { style: 'text-align:center; padding:20px; color:var(--muted-text); font-size:13px;' },
          vaultItems.length ? 'No matching accounts.' : 'No accounts in vault yet.'));
        return;
      }

      filtered.forEach((item) => {
        const revealed = revealedIds.has(item.id);
        const card = h('div', { class: 'vault-item', dataset: { id: item.id } });

        const head = h('div', { class: 'vault-item-header' });
        const info = h('div');
        info.appendChild(h('div', { class: 'vault-item-title' }, item.service));
        info.appendChild(h('div', { class: 'vault-item-user' }, item.username));
        head.appendChild(info);
        head.appendChild(h('span', { class: 'badge-tag' }, 'Encrypted'));
        card.appendChild(head);

        const row = h('div', { class: 'vault-item-row' });
        row.appendChild(h('div', { class: 'vault-pass', 'aria-label': revealed ? 'Password' : 'Password hidden' },
          revealed ? item.password : '••••••••••'));
        row.appendChild(h('button', { class: 'btn-action secondary', type: 'button', 'data-action': 'toggle', 'aria-pressed': String(revealed) }, revealed ? 'Hide' : 'Show'));
        row.appendChild(h('button', { class: 'btn-action', type: 'button', 'data-action': 'copy' }, 'Copy'));
        row.appendChild(h('button', { class: 'btn-action danger', type: 'button', 'data-action': 'delete', 'aria-label': 'Delete ' + item.service }, '✕'));
        card.appendChild(row);

        container.appendChild(card);
      });
    }

    // One delegated handler; actions use stable item ids, never list positions.
    $('vault-items-container').addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const card = btn.closest('.vault-item');
      if (!card) return;
      const id = card.dataset.id;
      const item = vaultItems.find((i) => i.id === id);
      if (!item) return;

      const action = btn.dataset.action;
      if (action === 'copy') {
        copyToClipboard(item.password);
      } else if (action === 'toggle') {
        if (revealedIds.has(id)) revealedIds.delete(id); else revealedIds.add(id);
        renderVaultList();
      } else if (action === 'delete') {
        const ok = await confirmDialog(`Delete "${item.service}"${item.username ? ' (' + item.username + ')' : ''} from the vault? This cannot be undone.`, 'Delete');
        if (!ok) return;
        const before = vaultItems;
        vaultItems = vaultItems.filter((i) => i.id !== id);
        revealedIds.delete(id);
        renderVaultList();
        try { await saveVaultItems(); showToast('Item deleted.'); }
        catch (err) { vaultItems = before; showToast('Delete failed. Nothing was changed.'); await recoverAfterFailedSave(); }
      }
    });

    $('vault-search').addEventListener('input', renderVaultList);

    // ---------------------------------------------------------------------
    // Add / save entry
    // ---------------------------------------------------------------------
    const modalSave = $('modal-save');

    // Pre-fill the service name with the current site (uses the activeTab permission).
    async function prefillService() {
      try {
        if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) return;
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const url = tabs && tabs[0] && tabs[0].url;
        if (url && /^https?:/i.test(url)) {
          const host = new URL(url).hostname.replace(/^www\./, '');
          if (!$('save-item-service').value) $('save-item-service').value = host;
        }
      } catch (e) { /* optional nicety */ }
    }

    function openSaveModal(prefillPassword) {
      $('save-item-password').value = prefillPassword || '';
      $('save-item-service').value = '';
      $('save-item-username').value = '';
      openModal(modalSave, 'save-item-service');
      prefillService();
    }

    $('save-to-vault-btn').addEventListener('click', () => {
      if (!currentPassword) { showToast('Generate a password first!'); return; }
      if (!masterCryptoKey) {
        showToast('Please unlock/set up your vault first.');
        tabVault.click();
        return;
      }
      openSaveModal(currentPassword);
    });

    $('add-entry-btn').addEventListener('click', () => openSaveModal(''));
    $('cancel-save-btn').addEventListener('click', () => {
      ['save-item-service', 'save-item-username', 'save-item-password'].forEach((id) => { $(id).value = ''; });
      closeModal(modalSave);
    });

    $('confirm-save-btn').addEventListener('click', async () => {
      const service = $('save-item-service').value.trim();
      const username = $('save-item-username').value.trim();
      const password = $('save-item-password').value;

      if (!service || !password) { showToast('Service and password required.'); return; }
      if (!masterCryptoKey) { closeModal(modalSave); return; }

      const entry = { id: newId(), service, username, password };
      vaultItems.push(entry);
      renderVaultList();
      try {
        await saveVaultItems();
        ['save-item-service', 'save-item-username', 'save-item-password'].forEach((id) => { $(id).value = ''; });
        closeModal(modalSave);
        showToast('Saved to vault!');
      } catch (err) {
        vaultItems = vaultItems.filter((i) => i.id !== entry.id);
        renderVaultList();
        showToast('Save failed. Nothing was stored.');
        await recoverAfterFailedSave();
      }
    });

    // ---------------------------------------------------------------------
    // Change master passphrase
    // ---------------------------------------------------------------------
    const modalPass = $('modal-pass');

    function clearPassModal() {
      ['pass-current', 'pass-new', 'pass-new-confirm'].forEach((id) => { $(id).value = ''; });
      $('pass-error').textContent = '';
    }

    $('change-pass-btn').addEventListener('click', () => { clearPassModal(); openModal(modalPass, 'pass-current', () => { clearPassModal(); closeModal(modalPass); }); });
    $('cancel-pass-btn').addEventListener('click', () => { clearPassModal(); closeModal(modalPass); });

    $('confirm-pass-btn').addEventListener('click', async () => {
      const current = $('pass-current').value;
      const next = $('pass-new').value;
      const next2 = $('pass-new-confirm').value;
      const err = $('pass-error');
      err.textContent = '';

      if (!current || !next) { err.textContent = 'Fill in all fields.'; return; }
      if (next.length < MIN_PASSPHRASE_LEN) { err.textContent = `New passphrase must be at least ${MIN_PASSPHRASE_LEN} characters.`; return; }
      if (next !== next2) { err.textContent = 'New passphrases do not match.'; return; }
      if (next === current) { err.textContent = 'New passphrase must be different.'; return; }

      const btn = $('confirm-pass-btn');
      btn.disabled = true;
      try {
        const meta = await dbGet('meta');
        if (!meta || !(await verifyPassphrase(current, meta))) { err.textContent = 'Current passphrase is incorrect.'; return; }
        await rekey(next);
        clearPassModal();
        closeModal(modalPass);
        showToast('Passphrase changed. Export a fresh backup.');
      } catch (e) {
        err.textContent = 'Could not change passphrase: ' + (e && e.message ? e.message : 'error');
      } finally {
        btn.disabled = false;
      }
    });

    // ---------------------------------------------------------------------
    // Backup export / import
    // ---------------------------------------------------------------------
    $('export-backup-btn').addEventListener('click', async () => {
      try {
        const meta = await dbGet('meta');
        const dataObj = await dbGet('data');
        if (!meta || !dataObj) { showToast('Vault is empty.'); return; }

        const backup = {
          app: 'FortifyGenVault',
          version: '1.3',
          timestamp: new Date().toISOString(),
          meta,
          vault: dataObj
        };
        const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fortify_vault_backup_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast('Encrypted backup downloaded!');
      } catch (e) {
        showToast('Export failed: ' + (e && e.message ? e.message : 'error'));
      }
    });

    function openInTab() {
      const url = location.pathname.split('/').pop() + '?tab=1';
      try {
        if (typeof chrome !== 'undefined' && chrome.tabs && chrome.runtime) {
          chrome.tabs.create({ url: chrome.runtime.getURL(url) });
          return true;
        }
      } catch (e) { /* fall through */ }
      return false;
    }
    $('expand-btn').addEventListener('click', () => { if (!openInTab()) showToast('Could not open a tab.'); });

    // Chrome closes the popup when the file picker opens, so importing happens in a full tab.
    $('import-backup-btn').addEventListener('click', () => {
      if (!IS_TAB) {
        if (openInTab()) { showToast('Opened in a tab. Unlock there and import.'); return; }
      }
      $('import-file-input').click();
    });

    function isByteArray(a, maxLen) {
      return Array.isArray(a) && a.length > 0 && a.length <= maxLen && a.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
    }

    // Returns sanitised records or null. Ids are forced; unknown fields are dropped.
    function sanitizeBackup(parsed) {
      if (!parsed || parsed.app !== 'FortifyGenVault' || !parsed.meta || !parsed.vault) return null;
      const m = parsed.meta, v = parsed.vault;
      const MAX = MAX_IMPORT_BYTES;
      if (!isByteArray(m.salt, 64)) return null;
      if (!m.checkToken || !isByteArray(m.checkToken.iv, 12) || m.checkToken.iv.length !== 12 || !isByteArray(m.checkToken.ciphertext, 1024)) return null;
      if (!v.encryptedData || !isByteArray(v.encryptedData.iv, 12) || v.encryptedData.iv.length !== 12 || !isByteArray(v.encryptedData.ciphertext, MAX)) return null;

      let iterations = LEGACY_ITERATIONS;
      if (m.iterations !== undefined) {
        if (!Number.isInteger(m.iterations) || m.iterations < LEGACY_ITERATIONS || m.iterations > 5000000) return null;
        iterations = m.iterations;
      }
      return [
        { id: 'meta', salt: m.salt.slice(), iterations, checkToken: { iv: m.checkToken.iv.slice(), ciphertext: m.checkToken.ciphertext.slice() } },
        { id: 'data', encryptedData: { iv: v.encryptedData.iv.slice(), ciphertext: v.encryptedData.ciphertext.slice() } }
      ];
    }

    $('import-file-input').addEventListener('change', (e) => {
      const input = e.target;
      const file = input.files && input.files[0];
      input.value = '';
      if (!file) return;
      if (file.size > MAX_IMPORT_BYTES) { showToast('Backup file is too large.'); return; }

      const reader = new FileReader();
      reader.onload = async (event) => {
        let records;
        try { records = sanitizeBackup(JSON.parse(event.target.result)); }
        catch (err) { records = null; }
        if (!records) { showToast('Invalid FortifyGen backup file.'); return; }

        const ok = await confirmDialog('This replaces the vault on this device with the backup. Anything saved here that is not in the backup will be lost. Export your current vault first if unsure.', 'Replace vault');
        if (!ok) return;

        try {
          await saveChain.catch(() => {});
          await dbPutMany(records);
          notifyOtherTabs('meta');
          lockVault('Vault restored. Unlock with the backup\'s passphrase.');
        } catch (err) {
          showToast('Import failed. Your current vault is unchanged.');
        }
      };
      reader.onerror = () => showToast('Could not read the file.');
      reader.readAsText(file);
    });

    // ---------------------------------------------------------------------
    // Generator + theme wiring
    // ---------------------------------------------------------------------
    generateBtn.addEventListener('click', generatePassword);
    copyBtn.addEventListener('click', () => copyToClipboard(currentPassword));

    toggleVisibilityBtn.addEventListener('click', () => {
      isMasked = !isMasked;
      visibilityText.textContent = isMasked ? 'Show' : 'Hide';
      toggleVisibilityBtn.setAttribute('aria-pressed', String(isMasked));
      toggleVisibilityBtn.title = isMasked ? 'Show password' : 'Hide password';
      updatePasswordDisplay();
    });

    function safeStorage(op, key, value) {
      try { return op === 'get' ? localStorage.getItem(key) : localStorage.setItem(key, value); }
      catch (e) { return null; }
    }

    themeToggle.addEventListener('change', (e) => {
      document.body.classList.toggle('light-mode', e.target.checked);
      safeStorage('set', 'fortifyTheme', e.target.checked ? 'light' : 'dark');
    });

    window.addEventListener('DOMContentLoaded', () => {
      if (safeStorage('get', 'fortifyTheme') === 'light') {
        themeToggle.checked = true;
        document.body.classList.add('light-mode');
      }
      generatePassword();
    });
