$(document).ready(function() {
    // Initialize Parsley validation
    $('#forgotPasswordForm').parsley();

    // Handle form submission
    $('#forgotPasswordForm').on('submit', function(e) {
        const $form = $(this);
        const $button = $('#submitButton');
        const $spinner = $button.find('.spinner-border');

        if ($form.parsley().isValid()) {
            // Show loading spinner
            $spinner.removeClass('d-none');
            $button.prop('disabled', true);
            return true;
        } else {
            e.preventDefault();
            return false;
        }
    });

    // Reset button state on form reset
    $('#forgotPasswordForm').on('reset', function() {
        const $button = $('#submitButton');
        const $spinner = $button.find('.spinner-border');
        $spinner.addClass('d-none');
        $button.prop('disabled', false);
    });
});