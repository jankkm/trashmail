/* Small progressive-enhancement helpers. The app works without JS except dialogs/menus. */
(() => {
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // confirm before destructive actions: <button data-confirm="Really?">
  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-confirm]');
    if (el && !window.confirm(el.dataset.confirm)) { e.preventDefault(); e.stopPropagation(); }
  }, true);

  // dialogs: [data-open="id"], [data-close], backdrop click
  document.addEventListener('click', (e) => {
    const opener = e.target.closest('[data-open]');
    if (opener) { const d = document.getElementById(opener.dataset.open); if (d) { d.showModal(); const f = d.querySelector('input:not([type=hidden]),select'); if (f) f.focus(); } }
    const closer = e.target.closest('[data-close]');
    if (closer) closer.closest('dialog').close();
    if (e.target instanceof HTMLDialogElement) e.target.close();
    // close popover menus on outside click
    $$('details.menu[open]').forEach((d) => { if (!d.contains(e.target)) d.open = false; });
  });
  $$('dialog[data-autoopen]').forEach((d) => d.showModal());

  // toasts
  $$('.toast').forEach((t) => {
    const hide = () => { t.classList.add('out'); setTimeout(() => t.remove(), 300); };
    t.querySelector('button')?.addEventListener('click', hide);
    setTimeout(hide, t.classList.contains('err') ? 9000 : 4500);
  });

  // inbox bulk selection
  const bulk = document.querySelector('[data-bulk]');
  if (bulk) {
    const boxes = () => $$('input.sel', bulk);
    const bar = bulk.querySelector('.bulkbar');
    const count = bulk.querySelector('[data-count]');
    const master = bulk.querySelector('input.sel-all');
    const sync = () => {
      const n = boxes().filter((b) => b.checked).length;
      if (bar) bar.hidden = n === 0;
      if (count) count.textContent = n;
      if (master) master.checked = n > 0 && n === boxes().length;
    };
    bulk.addEventListener('change', (e) => {
      if (e.target === master) boxes().forEach((b) => { b.checked = master.checked; });
      sync();
    });
    sync();
  }

  // settings: show the save bar once something changed
  const sform = document.querySelector('form[data-dirty]');
  if (sform) {
    const bar = document.getElementById('savebar');
    sform.addEventListener('input', () => { bar.hidden = false; });
    sform.addEventListener('change', () => { bar.hidden = false; });
  }

  // rule dialog: header-name + forward address only when relevant
  $$('form[data-rule-form]').forEach((f) => {
    const field = f.querySelector('[name=field]'), header = f.querySelector('[data-header]');
    const action = f.querySelector('[name=action]'), arg = f.querySelector('[data-forward]');
    const sync = () => {
      if (header) header.hidden = field.value !== 'header';
      if (arg) { arg.hidden = action.value !== 'forward'; arg.querySelector('input').required = action.value === 'forward'; }
    };
    field?.addEventListener('change', sync); action?.addEventListener('change', sync); sync();
  });
})();
