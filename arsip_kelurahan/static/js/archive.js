document.addEventListener('DOMContentLoaded', function() {
  const deleteButtons = document.querySelectorAll('.delete-btn');
  const deleteModalElement = document.getElementById('deleteModal');
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  const deleteArchiveTitle = document.getElementById('deleteArchiveTitle');

  // Validate required DOM elements
  if (!deleteModalElement || !confirmDeleteBtn || !deleteArchiveTitle) {
    console.error('Delete modal elements not found');
    return;
  }

  const deleteModal = new bootstrap.Modal(deleteModalElement);

  deleteButtons.forEach(button => {
    button.addEventListener('click', function() {
      const archiveId = this.getAttribute('data-id');
      const archiveTitle = this.getAttribute('data-title');

      if (!archiveId || isNaN(archiveId)) {
        showAlert('danger', 'ID arsip tidak valid');
        return;
      }

      deleteArchiveTitle.textContent = archiveTitle || 'Dokumen Tanpa Judul';
      confirmDeleteBtn.setAttribute('data-id', archiveId);
      deleteModal.show();
    });
  });

  confirmDeleteBtn.addEventListener('click', async function() {
    const archiveId = this.getAttribute('data-id');
    const csrfTokenInput = document.querySelector('input[name="csrf_token"]');

    if (!csrfTokenInput) {
      showAlert('danger', 'Token CSRF tidak ditemukan');
      deleteModal.hide();
      return;
    }

    const csrfToken = csrfTokenInput.value;

    if (!archiveId || isNaN(archiveId)) {
      showAlert('danger', 'ID arsip tidak valid');
      deleteModal.hide();
      return;
    }

    try {
      const response = await fetch(`/archives/delete/${archiveId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        }
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Gagal menghapus arsip');
      }

      showAlert('success', data.message || 'Arsip berhasil dihapus');
      deleteModal.hide();
      
      // Update result count
      const resultCount = document.getElementById('resultCount');
      if (resultCount) {
        const currentCount = parseInt(resultCount.textContent) || 0;
        resultCount.textContent = `${Math.max(0, currentCount - 1)} Arsip`;
      }

      // Remove the deleted row or reload if necessary
      const deletedRow = document.querySelector(`tr:has(button[data-id="${archiveId}"])`);
      const deletedGrid = document.querySelector(`.col:has(button[data-id="${archiveId}"])`);
      if (deletedRow) deletedRow.remove();
      if (deletedGrid) deletedGrid.remove();

      // If no archives remain, show empty state
      const archiveTable = document.getElementById('archiveTable');
      if (archiveTable && archiveTable.children.length === 0) {
        archiveTable.innerHTML = `
          <tr>
            <td colspan="5" class="text-center py-5">
              <div class="empty-state">
                <i class="bi bi-folder-x"></i>
                <h5 class="mt-3 mb-1">Tidak Ada Arsip</h5>
                <p class="text-muted">Belum ada arsip yang tersedia. Coba periksa filter atau tambah arsip baru.</p>
                <a href="/archives/upload" class="btn btn-primary mt-3">
                  <i class="bi bi-plus-lg me-1"></i>Tambah Arsip
                </a>
              </div>
            </td>
          </tr>
        `;
      }

    } catch (error) {
      console.error('Delete error:', error);
      showAlert('danger', `Gagal menghapus arsip: ${error.message}`);
    }
  });

  function showAlert(type, message) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.setAttribute('role', 'alert');
    alert.style.position = 'fixed';
    alert.style.top = '20px';
    alert.style.left = '50%';
    alert.style.transform = 'translateX(-50%)';
    alert.style.zIndex = '2000';
    alert.style.maxWidth = '600px';
    alert.innerHTML = `
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Tutup"></button>
    `;
    document.body.appendChild(alert);
    alert.focus(); // Improve accessibility
    setTimeout(() => {
      alert.classList.remove('show');
      setTimeout(() => alert.remove(), 150);
    }, 5000);
  }
});