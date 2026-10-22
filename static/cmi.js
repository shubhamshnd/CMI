// Conditional fields: show an element only when an earlier field has the given value.
// Hidden inputs are disabled so they are neither required nor submitted (the server applies the same rule).
function refreshConditions(form) {
  form.querySelectorAll('[data-show-field]').forEach(el => {
    const inputs = [...form.querySelectorAll(`[name="${CSS.escape(el.dataset.showField)}"]`)].filter(i => !i.disabled);
    const values = inputs.flatMap(i =>
      i.tagName === 'SELECT' ? [...i.selectedOptions].map(o => o.value)
      : (i.type === 'checkbox' || i.type === 'radio') ? (i.checked ? [i.value] : [])
      : [i.value]);
    const show = values.includes(el.dataset.showValue);
    el.hidden = !show;
    el.querySelectorAll('input, select, textarea').forEach(i => { i.disabled = !show; });
  });
}
document.querySelectorAll('form[data-dynamic]').forEach(form => {
  form.addEventListener('change', () => refreshConditions(form));
  refreshConditions(form);
});

// Row editors (form builder, workflow stages): add, remove and reorder rows.
document.querySelectorAll('[data-rows]').forEach(box => {
  const list = box.querySelector('.rows');
  const tpl = box.querySelector('template');
  box.addEventListener('click', e => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    e.preventDefault();
    const row = btn.closest('.row');
    if (btn.dataset.act === 'add') list.append(tpl.content.cloneNode(true));
    if (btn.dataset.act === 'del') row.remove();
    if (btn.dataset.act === 'up' && row.previousElementSibling) list.insertBefore(row, row.previousElementSibling);
    if (btn.dataset.act === 'down' && row.nextElementSibling) list.insertBefore(row.nextElementSibling, row);
  });
});

// Form builder: only show the settings that apply to each field's type (hidden inputs still submit, keeping rows aligned).
function refreshTypeSettings(row) {
  const type = row.querySelector('[name="f_type"]')?.value;
  row.querySelectorAll('[data-for]').forEach(el => { el.hidden = !el.dataset.for.split(' ').includes(type); });
}
document.querySelectorAll('[data-rows]').forEach(box => {
  box.querySelectorAll('.row').forEach(refreshTypeSettings);
  box.addEventListener('change', e => { if (e.target.name === 'f_type') refreshTypeSettings(e.target.closest('.row')); });
  new MutationObserver(() => box.querySelectorAll('.row').forEach(refreshTypeSettings)).observe(box.querySelector('.rows'), {childList: true});
});

// Ask before destructive actions: <form data-confirm="Are you sure…?">
document.addEventListener('submit', e => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
