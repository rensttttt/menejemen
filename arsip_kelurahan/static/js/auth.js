document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".toggle-password").forEach((btn) => {
        btn.addEventListener("click", function () {
            const input = this.parentElement.querySelector(".password-field");
            if (input.type === "password") {
                input.type = "text";
                this.querySelector("i").classList.replace("bi-eye", "bi-eye-slash");
            } else {
                input.type = "password";
                this.querySelector("i").classList.replace("bi-eye-slash", "bi-eye");
            }
        });
    });
});
