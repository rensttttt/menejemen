document.addEventListener('DOMContentLoaded', function() {
    // Password visibility toggle
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    
    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', function() {
            const passwordInput = this.parentElement.querySelector('input');
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

    // Form submission handling
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitButton = this.querySelector('button[type="submit"]');
            const spinner = submitButton.querySelector('.spinner-border');
            
            // Show loading state
            submitButton.disabled = true;
            spinner.classList.remove('d-none');
            
            // Client-side validation
            const username = this.querySelector('#username').value.trim();
            const password = this.querySelector('#password').value.trim();
            
            if (!username || !password) {
                showAlert('danger', 'Username dan password wajib diisi');
                submitButton.disabled = false;
                spinner.classList.add('d-none');
                return;
            }
            
            // Prepare form data
            const formData = new FormData(this);
            
            // AJAX login request
            fetch(this.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Redirect on successful login
                    window.location.href = data.redirect || '/dashboard';
                } else {
                    showAlert('danger', data.message || 'Login gagal');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('danger', 'Terjadi kesalahan saat proses login');
            })
            .finally(() => {
                submitButton.disabled = false;
                spinner.classList.add('d-none');
            });
        });
    }

    // Flash message auto-dismiss
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            setTimeout(() => alert.remove(), 150);
        }, 5000);
    });

    // Helper function to show alert messages
    function showAlert(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        const container = document.querySelector('.login-body');
        container.insertBefore(alertDiv, container.firstChild);
        
        setTimeout(() => {
            alertDiv.classList.add('fade');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }

    // Parsley form validation initialization
    if (window.Parsley) {
        $('#loginForm').parsley({
            errorClass: 'is-invalid',
            successClass: 'is-valid',
            errorsWrapper: '<div class="invalid-feedback"></div>',
            errorTemplate: '<span></span>',
            trigger: 'change'
        });
    }
});