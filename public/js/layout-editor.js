/* =====================================
   Layout Editor & Auto-Docking Engine
   ===================================== */

const DOCK_MARGIN = 16;
const SAFE_TOP = 80;
const SAFE_BOTTOM = 80;

function snapToDock(el) {
  const rect = el.getBoundingClientRect();
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  const positions = [
    { x: DOCK_MARGIN, y: SAFE_TOP },
    { x: vw - rect.width - DOCK_MARGIN, y: SAFE_TOP },
    { x: DOCK_MARGIN, y: vh - rect.height - SAFE_BOTTOM },
    { x: vw - rect.width - DOCK_MARGIN, y: vh - rect.height - SAFE_BOTTOM }
  ];

  let best = positions[0];
  let dist = Infinity;

  positions.forEach(p => {
    const d = (rect.left - p.x) ** 2 + (rect.top - p.y) ** 2;
    if (d < dist) { dist = d; best = p; }
  });

  el.style.left = best.x + 'px';
  el.style.top = best.y + 'px';
  localStorage.setItem('dock-' + el.id, JSON.stringify(best));
}

function restoreDock(el) {
  const saved = localStorage.getItem('dock-' + el.id);
  if (!saved) return;
  const { x, y } = JSON.parse(saved);
  el.style.left = x + 'px';
  el.style.top = y + 'px';
}

function enableDrag(el) {
  let startX, startY;

  el.addEventListener('pointerdown', e => {
    if (!document.body.classList.contains('layout-edit-mode')) return;
    el.classList.add('dragging');
    startX = e.clientX - el.offsetLeft;
    startY = e.clientY - el.offsetTop;

    const move = e => {
      el.style.left = e.clientX - startX + 'px';
      el.style.top = e.clientY - startY + 'px';
    };

    const up = () => {
      el.classList.remove('dragging');
      snapToDock(el);
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
    };

    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  });
}

/* ===============================
   GRID LAYOUT PERSISTENCE
   =============================== */

function saveGridLayout() {
  const layout = [...document.querySelectorAll('.grid-widget')].map(w => ({
    id: w.id,
    col: w.dataset.col,
    row: w.dataset.row,
    index: [...w.parentNode.children].indexOf(w)
  }));
  localStorage.setItem('grid-layout', JSON.stringify(layout));
}

function restoreGridLayout() {
  const saved = localStorage.getItem('grid-layout');
  if (!saved) return;
  const layout = JSON.parse(saved);
  const grid = document.querySelector('.layout-grid');

  layout.sort((a,b)=>a.index-b.index).forEach(item => {
    const el = document.getElementById(item.id);
    if (!el) return;
    el.dataset.col = item.col;
    el.dataset.row = item.row;
    el.style.gridColumn = 'span ' + item.col;
    el.style.gridRow = 'span ' + item.row;
    grid.appendChild(el);
  });
}

/* ===============================
   EDIT MODE TOGGLE
   =============================== */

const toggle = document.getElementById('layoutEditToggle');

toggle?.addEventListener('click', () => {
  document.body.classList.toggle('layout-edit-mode');
  localStorage.setItem('layout-edit-mode', document.body.classList.contains('layout-edit-mode'));
  if (!document.body.classList.contains('layout-edit-mode')) saveGridLayout();
});

if (localStorage.getItem('layout-edit-mode') === 'true') {
  document.body.classList.add('layout-edit-mode');
}

/* ===============================
   INIT
   =============================== */

window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.draggable').forEach(el => {
    restoreDock(el);
    enableDrag(el);
  });
  restoreGridLayout();
});
