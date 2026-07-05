export function openModal(id) {
  document.getElementById(id)?.classList.add('open');
}

export function closeModal(id) {
  document.getElementById(id)?.classList.remove('open');
}

export function initModalOverlays() {
  document.querySelectorAll('.modal-overlay').forEach((mo) => {
    mo.addEventListener('click', (e) => {
      if (e.target === mo) closeModal(mo.id);
    });
  });
}

