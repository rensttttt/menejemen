document.addEventListener('DOMContentLoaded', function() {
    // Form validation for each step
    const registerForm = document.getElementById('registerForm');
    const nextBtn = document.getElementById('nextBtn');
    const resendOtpBtn = document.getElementById('resendOtp');
    const otpTimer = document.getElementById('otpTimer');
    
    // OTP Timer functionality
    if (resendOtpBtn && otpTimer) {
        let timeLeft = 60;
        const timerInterval = setInterval(() => {
            timeLeft--;
            otpTimer.textContent = `Tunggu ${timeLeft} detik untuk kirim ulang`;
            
            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                resendOtpBtn.style.display = 'inline-block';
                otpTimer.style.display = 'none';
            }
        }, 1000);

        resendOtpBtn.addEventListener('click', function(e) {
            e.preventDefault();
            // Send request to resend OTP
            fetch('/auth/resend-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    email: document.querySelector('[name="email"]').value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Kode OTP baru telah dikirim ke email Anda', 'success');
                    // Reset timer
                    timeLeft = 60;
                    resendOtpBtn.style.display = 'none';
                    otpTimer.style.display = 'inline-block';
                    const newTimerInterval = setInterval(() => {
                        timeLeft--;
                        otpTimer.textContent = `Tunggu ${timeLeft} detik untuk kirim ulang`;
                        
                        if (timeLeft <= 0) {
                            clearInterval(newTimerInterval);
                            resendOtpBtn.style.display = 'inline-block';
                            otpTimer.style.display = 'none';
                        }
                    }, 1000);
                } else {
                    showAlert(data.message || 'Gagal mengirim OTP', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Terjadi kesalahan saat mengirim OTP', 'danger');
            });
        });
    }

    // Password strength indicator
    const passwordInput = document.querySelector('[name="password"]');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            const strengthIndicator = document.createElement('div');
            strengthIndicator.className = 'password-strength mt-2';
            
            // Remove previous indicator if exists
            const existingIndicator = this.parentNode.querySelector('.password-strength');
            if (existingIndicator) {
                existingIndicator.remove();
            }
            
            if (password.length > 0) {
                let strength = 0;
                let messages = [];
                
                // Check length
                if (password.length >= 8) strength++;
                else messages.push('Minimal 8 karakter');
                
                // Check uppercase
                if (/[A-Z]/.test(password)) strength++;
                else messages.push('Huruf besar (A-Z)');
                
                // Check lowercase
                if (/[a-z]/.test(password)) strength++;
                else messages.push('Huruf kecil (a-z)');
                
                // Check numbers
                if (/[0-9]/.test(password)) strength++;
                else messages.push('Angka (0-9)');
                
                // Check special chars
                if (/[^A-Za-z0-9]/.test(password)) strength++;
                else messages.push('Karakter khusus (@#$%^&*)');
                
                // Create strength bar
                strengthIndicator.innerHTML = `
                    <div class="progress" style="height: 5px;">
                        <div class="progress-bar bg-${getStrengthColor(strength)}" 
                             role="progressbar" style="width: ${strength * 20}%">
                        </div>
                    </div>
                    <small class="text-muted">Kekuatan password: ${getStrengthText(strength)}</small>
                    ${messages.length > 0 ? `<small class="d-block text-muted">Saran: ${messages.join(', ')}</small>` : ''}
                `;
                
                this.parentNode.appendChild(strengthIndicator);
            }
        });
    }

    // Confirm password validation
    const confirmPasswordInput = document.querySelector('[name="confirm_password"]');
    if (confirmPasswordInput && passwordInput) {
        confirmPasswordInput.addEventListener('input', function() {
            if (this.value !== passwordInput.value) {
                this.classList.add('is-invalid');
                const feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                feedback.textContent = 'Password tidak cocok';
                
                // Remove previous feedback if exists
                const existingFeedback = this.parentNode.querySelector('.invalid-feedback');
                if (existingFeedback && existingFeedback.textContent === 'Password tidak cocok') {
                    existingFeedback.remove();
                }
                
                this.parentNode.appendChild(feedback);
            } else {
                this.classList.remove('is-invalid');
                const feedback = this.parentNode.querySelector('.invalid-feedback');
                if (feedback && feedback.textContent === 'Password tidak cocok') {
                    feedback.remove();
                }
            }
        });
    }

    // Phone number formatting
    const phoneInput = document.querySelector('[name="phone"]');
    if (phoneInput) {
        phoneInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
    }

    // Username validation
    const usernameInput = document.querySelector('[name="username"]');
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            this.value = this.value.toLowerCase().replace(/[^a-z0-9_]/g, '');
        });
    }

    // Helper functions
    function getStrengthColor(strength) {
        switch(strength) {
            case 1: return 'danger';
            case 2: return 'warning';
            case 3: return 'info';
            case 4: return 'primary';
            case 5: return 'success';
            default: return 'secondary';
        }
    }

    function getStrengthText(strength) {
        switch(strength) {
            case 1: return 'Sangat Lemah';
            case 2: return 'Lemah';
            case 3: return 'Sedang';
            case 4: return 'Kuat';
            case 5: return 'Sangat Kuat';
            default: return '';
        }
    }

    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert after the card header or at the top of the form
        const cardHeader = document.querySelector('.card-header');
        if (cardHeader) {
            cardHeader.parentNode.insertBefore(alertDiv, cardHeader.nextSibling);
        } else {
            registerForm.prepend(alertDiv);
        }
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alertDiv);
            bsAlert.close();
        }, 5000);
    }

    // Form submission handling
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            // Client-side validation can be added here if needed
            const currentStep = document.querySelector('input[name="step"]').value;
            
            // Special validation for final step
            if (currentStep === '3') {
                const finalAgreement = document.getElementById('finalAgreement');
                if (finalAgreement && !finalAgreement.checked) {
                    e.preventDefault();
                    showAlert('Anda harus menyetujui pernyataan terakhir untuk menyelesaikan pendaftaran', 'danger');
                    return;
                }
            }
            
            // Show loading state
            if (nextBtn) {
                nextBtn.disabled = true;
                nextBtn.innerHTML = `
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                    Memproses...
                `;
            }
        });
    }
});