document.addEventListener('DOMContentLoaded', () => {
  const searchForm = document.getElementById('searchForm');
  const searchInput = document.getElementById('searchInput');
  const categoryFilter = document.getElementById('categoryFilter');
  const dateFilter = document.getElementById('dateFilter');
  const resultCount = document.getElementById('resultCount');

  // Validate required DOM elements
  if (!searchForm || !searchInput || !categoryFilter || !dateFilter) {
    console.error('Search form elements not found');
    return;
  }

  // Function to validate search input
  const validateSearch = (query) => {
    query = query.trim();
    if (query.length < 3 && query.length > 0) {
      searchInput.classList.add('is-invalid');
      let feedback = searchInput.nextElementSibling;
      if (!feedback || !feedback.classList.contains('invalid-feedback')) {
        feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = 'Masukkan setidaknya 3 karakter untuk pencarian.';
        searchInput.parentNode.appendChild(feedback);
      }
      return false;
    } else {
      searchInput.classList.remove('is-invalid');
      const feedback = searchInput.nextElementSibling;
      if (feedback && feedback.classList.contains('invalid-feedback')) {
        feedback.remove();
      }
      return true;
    }
  };

  // Function to validate category filter
  const validateCategory = (categoryId) => {
    if (categoryId && isNaN(categoryId)) {
      categoryFilter.classList.add('is-invalid');
      let feedback = categoryFilter.nextElementSibling;
      if (!feedback || !feedback.classList.contains('invalid-feedback')) {
        feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = 'Kategori tidak valid.';
        categoryFilter.parentNode.appendChild(feedback);
      }
      return false;
    } else {
      categoryFilter.classList.remove('is-invalid');
      const feedback = categoryFilter.nextElementSibling;
      if (feedback && feedback.classList.contains('invalid-feedback')) {
        feedback.remove();
      }
      return true;
    }
  };

  // Debounced input validation (300ms)
  let debounceTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      validateSearch(searchInput.value);
    }, 300);
  });

  categoryFilter.addEventListener('change', () => {
    validateCategory(categoryFilter.value);
  });

  // Debounced form submission (500ms) to reduce server load
  let submitTimer;
  searchForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const query = searchInput.value.trim();
    const categoryId = categoryFilter.value;

    if (!validateSearch(query) || !validateCategory(categoryId)) {
      return;
    }

    clearTimeout(submitTimer);
    submitTimer = setTimeout(() => {
      searchForm.submit();
    }, 500);
  });

  // Improve accessibility for result count
  if (resultCount) {
    resultCount.setAttribute('aria-live', 'polite');
    resultCount.setAttribute('role', 'status');
  }

  // Initialize validation on page load
  validateSearch(searchInput.value);
  validateCategory(categoryFilter.value);
});