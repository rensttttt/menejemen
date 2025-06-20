document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.getElementById('csrfToken').value;
    const alertContainer = document.getElementById('alertContainer');

    // Show alert
    function showAlert(message, type = 'danger') {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} fade-in`;
        alert.innerHTML = `<i class="bi bi-exclamation-circle"></i> ${message}`;
        alertContainer.appendChild(alert);
        setTimeout(() => alert.remove(), 5000);
    }

    // Format date to local time (WIB)
    function formatDate(dateStr) {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        return date.toLocaleString('id-ID', {
            timeZone: 'Asia/Jakarta',
            dateStyle: 'medium',
            timeStyle: 'short'
        });
    }

    // Format relative time
    function formatRelativeTime(dateStr) {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.round(diffMs / 60000);
        const diffHours = Math.round(diffMs / 3600000);
        const diffDays = Math.round(diffMs / 86400000);

        if (diffMins < 60) return `${diffMins} menit lalu`;
        if (diffHours < 24) return `${diffHours} jam lalu`;
        if (diffDays < 7) return `${diffDays} hari lalu`;
        return formatDate(dateStr);
    }

    // Fetch profile data
    async function fetchProfile() {
        try {
            const response = await fetch('/api/profile', {
                method: 'GET',
                headers: {
                    'X-CSRF-Token': csrfToken,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) throw new Error('Gagal mengambil data profil');
            const data = await response.json();

            // Populate profile info
            document.getElementById('usernameDisplay').textContent = data.username || '-';
            document.getElementById('profileName').textContent = data.full_name || '-';
            document.getElementById('profileRole').textContent = data.is_superadmin ? 'Superadmin' : data.is_admin ? 'Admin' : 'Staff';
            document.getElementById('joinDate').textContent = formatDate(data.created_at);
            document.getElementById('profileAvatar').src = data.avatar_url || '/static/images/default-avatar.png';
            document.getElementById('navbarAvatar').src = data.avatar_url || '/static/images/default-avatar.png';
            document.getElementById('firstName').value = data.first_name || '';
            document.getElementById('lastName').value = data.last_name || '';
            document.getElementById('email').value = data.email || '';
            document.getElementById('phone').value = data.phone || '';
            document.getElementById('address').value = data.address || '';
            document.getElementById('position').value = data.position || '';
            document.getElementById('department').value = data.department || '';
            document.getElementById('accountStatus').textContent = data.is_active ? 'Aktif' : 'Nonaktif';
            document.getElementById('emailVerified').textContent = data.email_verified ? 'Ya' : 'Tidak';
            document.getElementById('lastLogin').textContent = formatDate(data.last_login);
            document.getElementById('activeDevices').textContent = `${data.active_sessions} perangkat`;
            document.getElementById('archiveCount').textContent = data.stats.archives;
            document.getElementById('commentCount').textContent = data.stats.comments;
            document.getElementById('activityCount').textContent = data.stats.activities;

            // Populate activity timeline
            const timeline = document.getElementById('activityTimeline');
            timeline.innerHTML = '';
            if (data.activities.length === 0) {
                timeline.innerHTML = '<p class="text-muted text-center">Belum ada aktivitas.</p>';
            } else {
                data.activities.forEach(activity => {
                    const item = document.createElement('div');
                    item.className = 'timeline-item';
                    item.innerHTML = `
                        <div class="timeline-date">${formatRelativeTime(activity.created_at)}</div>
                        <div class="timeline-content">${activity.description}</div>
                    `;
                    timeline.appendChild(item);
                });
            }

            // Populate sessions
            const sessionsList = document.getElementById('sessionsList');
            sessionsList.innerHTML = '';
            if (data.sessions.length === 0) {
                sessionsList.innerHTML = '<p class="text-muted text-center">Tidak ada sesi aktif.</p>';
            } else {
                data.sessions.forEach(session => {
                    const item = document.createElement('div');
                    item.className = 'session-item';
                    item.innerHTML = `
                        <div class="session-icon">
                            <i class="bi ${session.device.includes('Mobile') ? 'bi-phone' : 'bi-laptop'}"></i>
                        </div>
                        <div class="session-details">
                            <div class="session-device">${session.device}</div>
                            <div class="session-meta">
                                <span><i class="bi bi-geo-alt"></i> ${session.location || 'Tidak diketahui'}</span>
                                <span><i class="bi bi-clock"></i> ${formatRelativeTime(session.last_active)}</span>
                            </div>
                        </div>
                        <div class="session-actions">
                            <button class="btn btn-sm btn-outline-danger" data-session-id="${session.id}">
                                <i class="bi bi-box-arrow-right"></i> Keluar
                            </button>
                        </div>
                    `;
                    sessionsList.appendChild(item);
                });
            }

            // Add session logout handlers
            document.querySelectorAll('.session-item .btn-outline-danger').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const sessionId = btn.getAttribute('data-session-id');
                    try {
                        const response = await fetch(`/api/session/${sessionId}`, {
                            method: 'DELETE',
                            headers: {
                                'X-CSRF-Token': csrfToken,
                                'Content-Type': 'application/json'
                            }
                        });
                        if (!response.ok) throw new Error('Gagal mengakhiri sesi');
                        showAlert('Sesi berhasil diakhiri', 'success');
                        fetchProfile(); // Refresh data
                    } catch (error) {
                        showAlert(error.message);
                    }
                });
            });

        } catch (error) {
            showAlert(error.message);
        }
    }

    // Password toggle
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.previousElementSibling;
            const icon = btn.querySelector('i');
            input.type = input.type === 'password' ? 'text' : 'password';
            icon.classList.toggle('bi-eye');
            icon.classList.toggle('bi-eye-slash');
        });
    });

    // Avatar preview
    const avatarInput = document.getElementById('avatarInput');
    const avatarPreview = document.getElementById('avatarPreview');
    if (avatarInput && avatarPreview) {
        avatarInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    avatarPreview.src = event.target.result;
                };
                reader.readAsDataURL(file);
            }
        });
    }

    // Avatar form submission
    const avatarForm = document.getElementById('avatarForm');
    if (avatarForm) {
        avatarForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(avatarInput);
            try {
                const response = await fetch('/api/profile/avatar', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });
                if (!response.ok) throw new Error('Gagal mengunggah avatar');
                showAlert('Foto profil berhasil diperbarui', 'success');
                fetchProfile(); // Refresh data
                bootstrap.Modal.getInstance(document.getElementById('avatarModal')).hide();
            } catch (error) {
                document.getElementById('avatarError').textContent = error.message;
                document.getElementById('avatarError').classList.remove('d-none');
            }
        });
    }

    // Edit profile toggle
    const editProfileBtn = document.getElementById('editProfileBtn');
    const cancelEditBtn = document.getElementById('cancelEditBtn');
    const formButtons = document.getElementById('profileFormButtons');
    const formInputs = document.querySelectorAll('#profileForm input, #profileForm textarea');
    
    if (editProfileBtn) {
        editProfileBtn.addEventListener('click', () => {
            formInputs.forEach(input => input.readOnly = false);
            formButtons.classList.remove('d-none');
            editProfileBtn.classList.add('d-none');
        });
    }
    
    if (cancelEditBtn) {
        cancelEditBtn.addEventListener('click', () => {
            formInputs.forEach(input => input.readOnly = true);
            formButtons.classList.add('d-none');
            editProfileBtn.classList.remove('d-none');
            fetchProfile(); // Reset form
        });
    }

    // Initial fetch
    fetchProfile();
});