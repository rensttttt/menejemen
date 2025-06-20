// File: public/js/user.js
// Deskripsi: Logika pengelolaan akun pengguna di frontend

document.addEventListener('DOMContentLoaded', () => {
    const profileForm = document.querySelector('#profile-form');
    const userManagementButtons = document.querySelectorAll('.user-action-btn');

    // Validasi dan submit form profil
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const full_name = document.querySelector('#full_name').value.trim();
            const email = document.querySelector('#email').value.trim();
            const phone = document.querySelector('#phone').value.trim();
            const password = document.querySelector('#password').value;
            const errorDiv = document.querySelector('#profile-error');

            // Validasi sisi klien
            if (!full_name || !email) {
                errorDiv.textContent = 'Nama lengkap dan email wajib diisi';
                errorDiv.style.display = 'block';
                return;
            }

            if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
                errorDiv.textContent = 'Email tidak valid';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                const response = await fetch('/profile', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
                    },
                    body: JSON.stringify({ full_name, email, phone, password })
                });

                const data = await response.json();
                if (response.ok) {
                    window.location.reload();
                } else {
                    errorDiv.textContent = data.message || 'Gagal memperbarui profil';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Terjadi kesalahan, coba lagi nanti';
                errorDiv.style.display = 'block';
                console.error('Profile update error:', error);
            }
        });
    }

    // Aksi manajemen pengguna (aktivasi/deaktivasi oleh admin)
    userManagementButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const userId = button.dataset.userId;
            const action = button.dataset.action; // 'activate' atau 'deactivate'
            const confirmMessage = action === 'activate' 
                ? 'Apakah Anda yakin ingin mengaktifkan pengguna ini?'
                : 'Apakah Anda yakin ingin menonaktifkan pengguna ini?';

            if (!confirm(confirmMessage)) return;

            try {
                const response = await fetch(`/admin/users/${userId}/${action}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
                    }
                });

                const data = await response.json();
                if (response.ok) {
                    window.location.reload();
                } else {
                    alert(data.message || `Gagal ${action} pengguna`);
                }
            } catch (error) {
                alert('Terjadi kesalahan, coba lagi nanti');
                console.error('User action error:', error);
            }
        });
    });
});