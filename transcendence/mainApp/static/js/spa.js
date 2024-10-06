document.addEventListener('DOMContentLoaded', function () {
    const contentDiv = document.getElementById('content');

    function loadContent(url, addToHistory = true) {
        document.getElementById('loadingOverlay').style.display = 'block';

        fetch(url, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.text())
        .then(html => {
            contentDiv.innerHTML = html;
            if (addToHistory) {
                history.pushState({ url: url }, '', url);
            }
            attachEventListeners(); // Re-attach event listeners after loading new content
            document.dispatchEvent(new Event('spaContentLoaded')); // Trigger custom event
            document.getElementById('loadingOverlay').style.display = 'none';
        })
        .catch(error => {
            console.error('Error loading content:', error);
            contentDiv.innerHTML = '<p>Error loading content. Please try again.</p>';
            document.getElementById('loadingOverlay').style.display = 'none';
        });
    }

    function attachEventListeners() {
        document.querySelectorAll('a[data-url]').forEach(link => {
            link.addEventListener('click', function (e) {
                e.preventDefault();
                const url = this.getAttribute('data-url');
                loadContent(url);
            });
        });

        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function (e) {
                const inputVal = e.target.value;
                console.log('Search input:', inputVal); // Debugging log

                if (inputVal.length > 0) {
                    fetch(`/search_user/?term=${inputVal}`)
                        .then(response => response.json())
                        .then(data => {
                            console.log('Search results:', data); // Debugging log
                            let resultList = document.getElementById('searchResults');
                            resultList.innerHTML = ''; // Clear previous results
                            resultList.style.display = 'block'; // Show results list
                            data.forEach(user => {
                                let li = document.createElement('li');
                                li.innerHTML = `<a href="/user/${user.username}">${user.username}</a>`;
                                resultList.appendChild(li);
                            });
                        })
                        .catch(error => {
                            console.error('Error fetching search results:', error); // Debugging log
                        });
                } else {
                    document.getElementById('searchResults').style.display = 'none'; // Hide results list
                }
            });
        }

        const friendLabel = document.getElementById('friendLabel');
        if (friendLabel) {
            const removeFriendText = "{{ 'Verwijder vriend' |translate:request }}";
            const friendText = "{{ 'Vriend'|translate:request }}";
            friendLabel.addEventListener('mouseover', function () {
                this.textContent = removeFriendText;
            });
            friendLabel.addEventListener('mouseout', function () {
                this.textContent = friendText;
            });
            friendLabel.addEventListener('click', function () {
                const confirmed = confirm("{{ 'Are you sure you want to remove this friend?' |translate:request }}");
                if (confirmed) {
                    document.getElementById('removeFriendForm').submit();
                }
            });
        }

        // Add event listeners for carrousel (if exists)
        const carrousel = document.querySelector('.carrousel');
        if (carrousel) {
            let isDragging = false;
            let startPos = 0;
            let scrollLeft = 0;

            carrousel.addEventListener('mousedown', (e) => {
                isDragging = true;
                startPos = e.pageX - carrousel.offsetLeft;
                scrollLeft = carrousel.scrollLeft;
            });

            carrousel.addEventListener('mouseleave', () => {
                isDragging = false;
            });

            carrousel.addEventListener('mouseup', () => {
                isDragging = false;
            });

            carrousel.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                e.preventDefault();
                const x = e.pageX - carrousel.offsetLeft;
                const walk = (x - startPos) * 1; // Adjust scroll speed here if necessary
                carrousel.scrollLeft = scrollLeft - walk;
            });
        }

        {% if user.is_authenticated %}
        initChart();
        {% endif %}
    }

    window.addEventListener('popstate', function (e) {
        if (e.state && e.state.url) {
            loadContent(e.state.url, false);
        }
    });

    // Load initial content
    loadContent(window.location.pathname, false);
    attachEventListeners(); // Attach event listeners initially
});
