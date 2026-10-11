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

  // clickable star in the message list: flag/unflag in place (the button also works as a plain form post)
  document.addEventListener('click', async (e) => {
    const star = e.target.closest('button.star[formaction]');
    if (!star) return;
    const form = star.closest('form');
    if (!form || !window.fetch) return;             // fall back to the normal submit
    e.preventDefault();
    const was = star.classList.contains('on');
    const apply = (on) => {
      star.classList.toggle('on', on);
      star.setAttribute('aria-pressed', String(on));
      const label = on ? 'Remove flag' : 'Flag this message';
      star.title = label; star.setAttribute('aria-label', label);
    };
    apply(!was);                                     // optimistic
    try {
      const body = new URLSearchParams({ csrf: form.querySelector('[name=csrf]').value, next: '/' });
      const r = await fetch(star.getAttribute('formaction'), {
        method: 'POST', body, headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' });
      if (!r.ok) throw new Error(String(r.status));
    } catch (err) {
      apply(was);                                    // roll back and tell the user
      star.animate([{ transform: 'translateX(-3px)' }, { transform: 'translateX(3px)' }, { transform: 'none' }], 200);
    }
  });

  // forward without leaving the page: forms or buttons marked data-async-forward post with fetch
  const toast = (text, ok) => {
    let box = document.querySelector('.toasts');
    if (!box) { box = document.createElement('div'); box.className = 'toasts'; document.body.appendChild(box); }
    const t = document.createElement('div');
    t.className = 'toast ' + (ok ? 'ok' : 'err');
    t.setAttribute('role', ok ? 'status' : 'alert');
    const span = document.createElement('span'); span.textContent = text;
    const close = document.createElement('button'); close.setAttribute('aria-label', 'Dismiss'); close.textContent = '×';
    const hide = () => { t.classList.add('out'); setTimeout(() => t.remove(), 300); };
    close.addEventListener('click', hide);
    t.append(span, close); box.appendChild(t);
    setTimeout(hide, ok ? 4500 : 9000);
    return t;
  };
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-async-forward]');
    if (btn && !btn.closest('form[data-async-forward]')) { e.preventDefault(); sendForward(btn.closest('form'), btn, btn.getAttribute('formaction')); }
  });
  document.addEventListener('submit', (e) => {
    const f = e.target.closest('form[data-async-forward]');
    if (f) { e.preventDefault(); sendForward(f, f.querySelector('button:not([type=button])'), f.getAttribute('action')); }
  });
  async function sendForward(form, btn, url) {
    if (!window.fetch || !form || btn?.classList.contains('busy')) return;
    const to = form.querySelector('[name=to]');
    const mode = form.querySelector('select[name=mode]');
    const body = new URLSearchParams({ csrf: form.querySelector('[name=csrf]').value, to: to ? to.value : '' });
    if (mode) body.set('mode', mode.value);
    btn?.classList.add('busy'); btn?.setAttribute('aria-busy', 'true');
    const pending = toast('Sending…', true);
    try {
      const r = await fetch(url, { method: 'POST', body, credentials: 'same-origin',
                                   headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' } });
      const data = await r.json().catch(() => ({}));
      pending.remove();
      toast(data.message || (r.ok ? 'Sent' : 'Sending failed (' + r.status + ')'), r.ok);
      if (r.ok && to) to.value = '';
    } catch (err) {
      pending.remove();
      toast('Sending failed: network error', false);
    } finally {
      btn?.classList.remove('busy'); btn?.removeAttribute('aria-busy');
    }
  }

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

  // quick-rule form (message page): forward address only when relevant
  $$('form[data-rule-form]').forEach((f) => {
    const action = f.querySelector('[name=act_type]'), arg = f.querySelector('[data-forward]');
    const sync = () => {
      if (!arg) return;
      const needs = action.value === 'forward' || action.value === 'redirect' || action.value === 'tag';
      const input = arg.querySelector('input');
      arg.hidden = !needs;
      input.required = needs;
      const mail = action.value === 'forward' || action.value === 'redirect';
      input.type = mail ? 'email' : 'text';
      input.placeholder = mail ? 'Send to address' : 'Tag name';
    };
    action?.addEventListener('change', sync); sync();
  });

  // favorites: click a suggested address to add it to the textarea
  document.addEventListener('click', (e) => {
    const chip = e.target.closest('[data-add-address]');
    if (!chip) return;
    const box = chip.closest('form').querySelector('[data-addresses]');
    const have = box.value.split(/[\s,;]+/).filter(Boolean);
    if (!have.includes(chip.dataset.addAddress)) box.value = (box.value.trim() ? box.value.trim() + '\n' : '') + chip.dataset.addAddress;
    chip.classList.add('used');
  });

  // rule editor dialog: any number of conditions, one or more actions
  const editor = document.querySelector('[data-rule-editor]');
  if (editor) {
    const form = editor.querySelector('form');
    const conds = editor.querySelector('[data-conds]'), acts = editor.querySelector('[data-acts]');
    const tplCond = editor.querySelector('template[data-tpl-cond]'), tplAct = editor.querySelector('template[data-tpl-act]');
    const match = editor.querySelector('[data-match]'), hint = editor.querySelector('[data-cond-hint]');
    const sync = () => {
      const n = conds.children.length;
      match.hidden = n < 2;
      hint.hidden = n > 0;
      $$('.cond-row', conds).forEach((row) => {
        row.querySelector('[data-header]').hidden = row.querySelector('[name=cond_field]').value !== 'header';
        row.querySelector('[data-header]').required = !row.querySelector('[data-header]').hidden;
      });
      $$('.act-row', acts).forEach((row) => {
        const arg = row.querySelector('[data-arg]');
        const type = row.querySelector('[name=act_type]').value;
        const mail = type === 'forward' || type === 'redirect';
        arg.hidden = !mail && type !== 'tag';
        arg.required = !arg.hidden;
        arg.type = mail ? 'email' : 'text';
        arg.placeholder = mail ? 'name@example.com' : 'Tag name';
      });
      $$('[data-remove]', acts).forEach((b) => { b.hidden = acts.children.length < 2; });   // keep >= 1 action
    };
    const addCond = (c = {}) => {
      const row = tplCond.content.firstElementChild.cloneNode(true);
      row.querySelector('[name=cond_field]').value = c.field || 'sender';
      row.querySelector('[name=cond_header]').value = c.header || '';
      row.querySelector('[name=cond_op]').value = c.op || 'contains';
      row.querySelector('[name=cond_value]').value = c.value || '';
      conds.append(row); sync(); return row;
    };
    const addAct = (a = {}) => {
      const row = tplAct.content.firstElementChild.cloneNode(true);
      row.querySelector('[name=act_type]').value = a.action || 'flag';
      row.querySelector('[name=act_arg]').value = a.arg || '';
      acts.append(row); sync(); return row;
    };
    const reset = () => {
      conds.replaceChildren(); acts.replaceChildren();
      form.querySelector('[name=name]').value = '';
      form.querySelector('[name=scope]').value = '';
      form.querySelector('[name=priority]').value = '100';
      match.value = 'all';
    };
    editor.addEventListener('click', (e) => {
      if (e.target.closest('[data-add-cond]')) addCond({ field: 'sender' }).querySelector('[name=cond_value]').focus();
      else if (e.target.closest('[data-add-act]')) addAct();
      else {
        const rm = e.target.closest('[data-remove]');
        const row = rm && rm.closest('.edit-row');
        if (row && !(row.classList.contains('act-row') && acts.children.length < 2)) { row.remove(); sync(); }   // keep >= 1 action
      }
    });
    editor.addEventListener('change', sync);
    document.addEventListener('click', (e) => {
      const fresh = e.target.closest('[data-rule-new]');
      const edit = e.target.closest('[data-rule-edit]');
      if (!fresh && !edit) return;
      reset();
      if (fresh) {
        editor.querySelector('[data-title]').textContent = 'New rule';
        form.action = '/rules';
        form.querySelector('[name=scope]').value = fresh.dataset.scope || '';
        addAct({ action: 'flag' });
      } else {
        const rule = JSON.parse(edit.dataset.ruleEdit);
        editor.querySelector('[data-title]').textContent = 'Edit rule';
        form.action = `/rules/${rule.id}/update`;
        form.querySelector('[name=name]').value = rule.name;
        form.querySelector('[name=scope]').value = rule.scope;
        form.querySelector('[name=priority]').value = rule.priority;
        match.value = rule.match_mode;
        rule.conditions.forEach(addCond);
        (rule.actions.length ? rule.actions : [{ action: 'flag' }]).forEach(addAct);
      }
      sync();
      editor.showModal();
    });
  }
})();
