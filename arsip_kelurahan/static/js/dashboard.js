document.addEventListener('DOMContentLoaded', () => {
  // ==================== INITIAL SETUP ====================
  const dashboardWrapper = document.querySelector('.dashboard-wrapper');
  
  if (!dashboardWrapper) {
    console.error('Dashboard wrapper element not found');
    return;
  }

  // ==================== SIDEBAR MANAGEMENT ====================
  const toggleSidebar = () => {
    dashboardWrapper.classList.toggle('sidebar-collapsed');
    const isCollapsed = dashboardWrapper.classList.contains('sidebar-collapsed');
    localStorage.setItem('sidebarState', isCollapsed ? 'collapsed' : 'expanded');
    document.querySelector('.sidebar-toggle').setAttribute('aria-expanded', !isCollapsed);
  };

  const initSidebarState = () => {
    const sidebarState = localStorage.getItem('sidebarState');
    if (sidebarState === 'collapsed') {
      dashboardWrapper.classList.add('sidebar-collapsed');
      document.querySelector('.sidebar-toggle')?.setAttribute('aria-expanded', 'false');
    } else {
      document.querySelector('.sidebar-toggle')?.setAttribute('aria-expanded', 'true');
    }
  };

  const setupSidebarToggle = () => {
    const sidebarToggle = document.querySelector('.sidebar-toggle');
    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', toggleSidebar);
    } else {
      console.warn('Sidebar toggle button not found');
    }
  };

  const setupSidebarNavigation = () => {
    const sidebarMenu = document.querySelector('.sidebar-menu');
    if (!sidebarMenu) {
      console.warn('Sidebar menu not found');
      return;
    }

    sidebarMenu.addEventListener('click', (e) => {
      const target = e.target.closest('a');
      if (!target) return;

      // Handle submenu toggle
      if (target.parentElement.classList.contains('has-submenu')) {
        if (window.innerWidth > 992) {
          e.preventDefault();
          const parent = target.parentElement;
          const isActive = parent.classList.toggle('active');
          target.setAttribute('aria-expanded', isActive);
        }
        return;
      }

      // Handle regular sidebar links
      if (window.innerWidth < 992) {
        dashboardWrapper.classList.add('sidebar-collapsed');
        localStorage.setItem('sidebarState', 'collapsed');
        document.querySelector('.sidebar-toggle')?.setAttribute('aria-expanded', 'false');
      }
    });
  };

  // ==================== USER DROPDOWN MANAGEMENT ====================
  const setupUserDropdown = () => {
    const userDropdown = document.querySelector('.user-dropdown');
    if (!userDropdown) {
      console.warn('User dropdown not found');
      return;
    }

    userDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
      const isActive = userDropdown.classList.toggle('active');
      userDropdown.setAttribute('aria-expanded', isActive);
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.user-dropdown')) {
        userDropdown.classList.remove('active');
        userDropdown.setAttribute('aria-expanded', 'false');
      }
    });
  };

  // ==================== CHART INITIALIZATION ====================
  const initArchiveChart = () => {
    const chartCanvas = document.getElementById('archiveChart');
    if (!chartCanvas) {
      console.warn('Chart canvas not found');
      return;
    }

    if (typeof Chart === 'undefined') {
      console.warn('Chart.js is not loaded');
      return;
    }

    try {
      const labels = JSON.parse(chartCanvas.dataset.labels || '["Jan", "Feb", "Mar", "Apr", "Mei", "Jun"]');
      const values = JSON.parse(chartCanvas.dataset.values || '[0, 0, 0, 0, 0, 0]');
      const maxValue = Math.max(...values, 10);

      const ctx = chartCanvas.getContext('2d');
      const gradient = ctx.createLinearGradient(0, 0, 0, 300);
      gradient.addColorStop(0, 'rgba(37, 99, 235, 0.3)');
      gradient.addColorStop(1, 'rgba(37, 99, 235, 0.05)');

      new Chart(chartCanvas, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            label: 'Jumlah Arsip',
            data: values,
            fill: true,
            backgroundColor: gradient,
            borderColor: '#2563EB',
            borderWidth: 2,
            pointBackgroundColor: '#FFFFFF',
            pointBorderColor: '#2563EB',
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0.4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              mode: 'index',
              intersect: false,
              backgroundColor: '#111827',
              titleFont: { size: 14, weight: '600' },
              bodyFont: { size: 12 },
              padding: 12,
              cornerRadius: 8,
              displayColors: false,
              callbacks: {
                label: (context) => ` ${context.parsed.y} arsip`
              }
            }
          },
          scales: {
            x: {
              grid: { display: false, drawBorder: false },
              ticks: { color: '#6B7280', font: { size: 12 } }
            },
            y: {
              beginAtZero: true,
              max: Math.ceil(maxValue * 1.2),
              grid: { color: 'rgba(229, 231, 235, 0.5)', drawBorder: false },
              ticks: {
                color: '#6B7280',
                font: { size: 12 },
                stepSize: Math.max(1, Math.floor(maxValue / 5))
              }
            }
          },
          interaction: {
            mode: 'nearest',
            axis: 'x',
            intersect: false
          },
          animation: {
            duration: 1000,
            easing: 'easeOutQuart'
          }
        }
      });
    } catch (error) {
      console.error('Failed to initialize chart:', error);
    }
  };

  // ==================== STAT CARD ANIMATIONS ====================
  const setupStatCards = () => {
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach((card) => {
      card.style.transition = 'transform 0.3s ease, box-shadow 0.3s ease';
      card.addEventListener('mouseenter', () => {
        card.style.transform = 'translateY(-5px)';
        card.style.boxShadow = '0 10px 15px rgba(0, 0, 0, 0.15)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'none';
        card.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
      });
      card.addEventListener('focus', () => {
        card.style.transform = 'translateY(-5px)';
        card.style.boxShadow = '0 10px 15px rgba(0, 0, 0, 0.15)';
      });
      card.addEventListener('blur', () => {
        card.style.transform = 'none';
        card.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
      });
    });
  };

  // ==================== ACTIVE LINK HIGHLIGHTING ====================
  const setActiveLinks = () => {
    const currentPath = window.location.pathname;
    const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
    
    sidebarLinks.forEach((link) => {
      try {
        const linkPath = new URL(link.href, window.location.origin).pathname;
        const listItem = link.parentElement;
        
        if (currentPath === linkPath) {
          listItem.classList.add('active');
          const parentMenu = link.closest('.has-submenu');
          if (parentMenu) {
            parentMenu.classList.add('active');
            parentMenu.querySelector('a[aria-haspopup="true"]')?.setAttribute('aria-expanded', 'true');
          }
        } else {
          listItem.classList.remove('active');
        }
      } catch (e) {
        console.warn('Invalid link URL:', link.href);
      }
    });
  };

  // ==================== RESPONSIVE MANAGEMENT ====================
  const handleResponsive = () => {
    if (window.innerWidth >= 992) {
      const savedState = localStorage.getItem('sidebarState');
      if (savedState !== 'collapsed') {
        dashboardWrapper.classList.remove('sidebar-collapsed');
        document.querySelector('.sidebar-toggle')?.setAttribute('aria-expanded', 'true');
      }
    } else {
      dashboardWrapper.classList.add('sidebar-collapsed');
      document.querySelector('.sidebar-toggle')?.setAttribute('aria-expanded', 'false');
    }
  };

  const setupResponsive = () => {
    handleResponsive();
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(handleResponsive, 150);
    });
  };

  // ==================== INITIALIZE DASHBOARD ====================
  const initializeDashboard = () => {
    initSidebarState();
    setupSidebarToggle();
    setupSidebarNavigation();
    setupUserDropdown();
    initArchiveChart();
    setupStatCards();
    setActiveLinks();
    setupResponsive();
  };

  initializeDashboard();
});