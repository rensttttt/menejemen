/**
 * scripts.js - Kelurahan Digital Archiving System
 * Kumpulan fungsi JavaScript untuk sistem arsip digital kelurahan
 */

// Fungsi inisialisasi saat dokumen siap
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    initToasts();
    initPasswordToggle();
    initFormValidations();
    initDataTables();
    initFileUploads();
    initDarkModeToggle();
});

/**
 * Inisialisasi tooltip Bootstrap
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover'
        });
    });
}

/**
 * Inisialisasi toast Bootstrap
 */
function initToasts() {
    const toastElList = [].slice.call(document.querySelectorAll('.toast'));
    toastElList.map(function (toastEl) {
        const toast = new bootstrap.Toast(toastEl);
        toast.show();
    });
}

/**
 * Toggle show/hide password
 */
function initPasswordToggle() {
    const passwordToggles = document.querySelectorAll('.password-toggle');
    
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const passwordInput = this.previousElementSibling;
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        });
    });
}

/**
 * Validasi form umum
 */
function initFormValidations() {
    // Contoh validasi untuk form dengan class 'needs-validation'
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            form.classList.add('was-validated');
        }, false);
    });
}

/**
 * Inisialisasi DataTables
 */
function initDataTables() {
    const dataTables = document.querySelectorAll('.data-table');
    
    dataTables.forEach(table => {
        $(table).DataTable({
            responsive: true,
            language: {
                url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/id.json'
            },
            dom: '<"top"f>rt<"bottom"lip><"clear">',
            initComplete: function() {
                // Tambahkan class Bootstrap ke elemen pagination
                $('.dataTables_paginate').addClass('btn-group');
                $('.paginate_button').addClass('btn btn-sm btn-outline-primary');
                $('.paginate_button.current').addClass('active');
            }
        });
    });
}

/**
 * Inisialisasi file upload
 */
function initFileUploads() {
    const fileInputs = document.querySelectorAll('.custom-file-input');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'Pilih file';
            const label = this.nextElementSibling;
            label.textContent = fileName;
        });
    });
}

/**
 * Toggle dark mode
 */
function initDarkModeToggle() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            const htmlEl = document.documentElement;
            const currentTheme = htmlEl.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            htmlEl.setAttribute('data-bs-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            // Update icon
            const icon = this.querySelector('i');
            icon.classList.toggle('bi-moon-fill');
            icon.classList.toggle('bi-sun-fill');
        });
    }
    
    // Periksa preferensi tema yang disimpan
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
}

/**
 * Format ukuran file menjadi format yang mudah dibaca
 * @param {number} bytes - Ukuran file dalam bytes
 * @returns {string} - Ukuran file yang diformat
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format tanggal ke format lokal Indonesia
 * @param {string} dateString - String tanggal
 * @returns {string} - Tanggal yang diformat
 */
function formatLocalDate(dateString) {
    const options = { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    return new Date(dateString).toLocaleDateString('id-ID', options);
}

/**
 * Fungsi untuk menampilkan modal konfirmasi
 * @param {string} title - Judul modal
 * @param {string} message - Pesan konfirmasi
 * @param {function} callback - Fungsi yang akan dijalankan saat dikonfirmasi
 */
function showConfirmationModal(title, message, callback) {
    const modal = new bootstrap.Modal(document.getElementById('confirmationModal'));
    const modalTitle = document.getElementById('confirmationModalTitle');
    const modalBody = document.getElementById('confirmationModalBody');
    const confirmBtn = document.getElementById('confirmationModalConfirm');
    
    modalTitle.textContent = title;
    modalBody.textContent = message;
    
    // Hapus event listener sebelumnya untuk menghindari duplikasi
    confirmBtn.replaceWith(confirmBtn.cloneNode(true));
    document.getElementById('confirmationModalConfirm').addEventListener('click', function() {
        callback();
        modal.hide();
    });
    
    modal.show();
}

/**
 * Fungsi untuk menampilkan loading spinner
 * @param {boolean} show - Tampilkan atau sembunyikan spinner
 */
function toggleLoading(show = true) {
    const spinner = document.getElementById('loadingSpinner');
    if (spinner) {
        spinner.style.display = show ? 'flex' : 'none';
    }
}

// Export fungsi untuk penggunaan modular (jika diperlukan)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        formatFileSize,
        formatLocalDate,
        showConfirmationModal,
        toggleLoading
    };
}