document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const analyzeForm = document.getElementById('analyzeForm');
    const resetBtn = document.getElementById('resetBtn');
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');
    const resultsCard = document.getElementById('resultsCard');
    const placeholderCard = document.getElementById('placeholderCard');
    const csrfToken = document.getElementById('csrf_token').value;

    // Generator
    const generateBtn = document.getElementById('generateBtn');
    const copyBtn = document.getElementById('copyBtn');

    // Dashboard
    const refreshDashBtn = document.getElementById('refreshDashBtn');
    let chartInstance = null;

    // --- ANALYZER ---

    togglePassword.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePassword.innerHTML = type === 'password' ? '<i class="fa-solid fa-eye"></i>' : '<i class="fa-solid fa-eye-slash"></i>';
    });

    resetBtn.addEventListener('click', () => {
        analyzeForm.reset();
        resultsCard.style.display = 'none';
        placeholderCard.style.display = 'flex';
        passwordInput.setAttribute('type', 'password');
        togglePassword.innerHTML = '<i class="fa-solid fa-eye"></i>';
    });

    analyzeForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            platform: document.getElementById('platform').value,
            username: document.getElementById('username').value,
            password: passwordInput.value
        };

        try {
            const btn = analyzeForm.querySelector('button[type="submit"]');
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Analyzing...';
            btn.disabled = true;

            const res = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(payload)
            });

            const data = await res.json();

            if (res.ok) {
                updateResultsUI(data);
                loadDashboardData(); // Refresh dashboard silently
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
            }
        } catch (err) {
            console.error(err);
            alert('Failed to connect to the server.');
        } finally {
            const btn = analyzeForm.querySelector('button[type="submit"]');
            btn.innerHTML = '<i class="fa-solid fa-bolt me-2"></i>Analyze Security';
            btn.disabled = false;
        }
    });

    function updateResultsUI(data) {
        document.getElementById('resScore').innerText = data.score;
        document.getElementById('resEntropy').innerText = data.entropy;
        document.getElementById('resLength').innerText = data.length;

        const ratingEl = document.getElementById('resRating');
        ratingEl.innerText = data.rating;

        const bar = document.getElementById('scoreBar');
        bar.style.width = `${data.score}%`;

        // Colors based on score
        bar.className = 'progress-bar progress-bar-striped progress-bar-animated';
        if (data.score < 40) {
            bar.classList.add('bg-danger');
            ratingEl.className = 'fw-bold text-danger';
        } else if (data.score < 80) {
            bar.classList.add('bg-warning');
            ratingEl.className = 'fw-bold text-warning';
        } else {
            bar.classList.add('bg-success');
            ratingEl.className = 'fw-bold text-success';
        }

        // Crack Times
        document.getElementById('timeCommon').innerText = data.crack_times.common_list;
        document.getElementById('timeDict').innerText = data.crack_times.dictionary;
        document.getElementById('timeBrute').innerText = data.crack_times.brute_force;
        document.getElementById('timeGpu').innerText = data.crack_times.gpu;

        // Recs
        const recsList = document.getElementById('recsList');
        recsList.innerHTML = '';
        if (data.recommendations.length === 0) {
            recsList.innerHTML = '<li class="list-group-item"><i class="fa-solid fa-check text-success"></i> Password is excellent. No further recommendations.</li>';
        } else {
            data.recommendations.forEach(rec => {
                recsList.innerHTML += `<li class="list-group-item"><i class="fa-solid fa-circle-exclamation"></i> ${rec}</li>`;
            });
        }

        placeholderCard.style.display = 'none';
        resultsCard.style.display = 'block';
    }

    // --- GENERATOR ---

    generateBtn.addEventListener('click', async () => {
        const payload = {
            strength: document.getElementById('genStrength').value,
            length: document.getElementById('genLength').value
        };

        try {
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (res.ok) {
                document.getElementById('genResult').value = data.password;
            }
        } catch (e) {
            console.error(e);
        }
    });

    copyBtn.addEventListener('click', () => {
        const val = document.getElementById('genResult').value;
        if (val) {
            navigator.clipboard.writeText(val);
            copyBtn.innerHTML = '<i class="fa-solid fa-check text-success"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i>';
            }, 2000);
        }
    });

    // --- DASHBOARD ---

    refreshDashBtn.addEventListener('click', loadDashboardData);

    async function loadDashboardData() {
        try {
            const res = await fetch('/api/dashboard');
            if (!res.ok) return;
            const data = await res.json();

            document.getElementById('dashTotal').innerText = data.total;
            document.getElementById('dashAvg').innerText = data.average_score;
            document.getElementById('dashWeak').innerText = data.weak_count;
            document.getElementById('dashStrong').innerText = data.strong_count;

            const recentList = document.getElementById('dashRecent');
            recentList.innerHTML = '';
            data.recent.reverse().forEach(log => {
                recentList.innerHTML += `<li class="list-group-item text-muted" style="font-size: 0.85rem">${log}</li>`;
            });

            // Update Chart
            const ctx = document.getElementById('platformsChart').getContext('2d');
            const labels = Object.keys(data.platforms);
            const values = Object.values(data.platforms);

            if (chartInstance) {
                chartInstance.destroy();
            }

            chartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: [
                            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'
                        ],
                        borderColor: '#161c2d',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#cbd5e1' }
                        }
                    }
                }
            });

        } catch (e) {
            console.error("Dashboard error:", e);
        }
    }

    // Load initial data
    loadDashboardData();
    // Pre-generate a password
    generateBtn.click();
});
