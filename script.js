let captchaText = '';
let mouseMovements = [];

function generateCaptcha() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = 150;
    canvas.height = 50;

    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const captchaLength = 6;
    captchaText = '';
    for (let i = 0; i < captchaLength; i++) {
        captchaText += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    ctx.fillStyle = '#f2f2f2';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < 5; i++) {
        ctx.strokeStyle = getRandomColor();
        ctx.beginPath();
        ctx.moveTo(Math.random() * canvas.width, Math.random() * canvas.height);
        ctx.lineTo(Math.random() * canvas.width, Math.random() * canvas.height);
        ctx.stroke();
    }

    for (let i = 0; i < 30; i++) {
        ctx.fillStyle = getRandomColor();
        ctx.beginPath();
        ctx.arc(Math.random() * canvas.width, Math.random() * canvas.height, 1, 0, Math.PI * 2);
        ctx.fill();
    }

    ctx.font = 'bold 24px Comic Sans MS';
    ctx.fillStyle = '#000';
    ctx.setTransform(
        Math.cos(0.1), -Math.sin(0.1),
        Math.sin(0.1), Math.cos(0.1),
        20, 25
    );
    ctx.fillText(captchaText, 10, 30);

    ctx.setTransform(1, 0, 0, 1, 0, 0);

    document.getElementById('captcha').innerHTML = '';
    document.getElementById('captcha').appendChild(canvas);

    function getRandomColor() {
        const letters = '0123456789ABCDEF';
        let color = '#';
        for (let i = 0; i < 6; i++) {
            color += letters[Math.floor(Math.random() * 16)];
        }
        return color;
    }
}

generateCaptcha();

function trackMouseMovement(event) {
    mouseMovements.push({ x: event.clientX, y: event.clientY });
}

function analyzeMovements() {
    // Check if there are enough recorded movements
    if (mouseMovements.length < 10) {
        return false; // Not enough data to analyze, assume it's not suspicious
    }

    let suspicious = false;

    // Iterate through the recorded movements
    for (let i = 1; i < mouseMovements.length; i++) {
        // Calculate the difference in x and y coordinates between consecutive points
        const dx = mouseMovements[i].x - mouseMovements[i - 1].x;
        const dy = mouseMovements[i].y - mouseMovements[i - 1].y;

        // If the differences are too small, mark as suspicious
        if (Math.abs(dx) < 2 && Math.abs(dy) < 2) {
            suspicious = true;
            break; // Stop further checks if suspicious behavior is detected
        }
    }

    return suspicious; // Return the result of the analysis
}



let currentUser;

function setCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/";
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

async function login() {
    document.addEventListener('mousemove', trackMouseMovement);
    const suspicious = analyzeMovements();
    if (suspicious) {
        alert('Suspicious activity detected. Please login again.');
        document.removeEventListener('mousemove', trackMouseMovement);
        return;
    }
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const captchaInput = document.getElementById('captchaInput').value;

    if (captchaInput.toLowerCase() !== captchaText.toLowerCase()) {
        alert('Invalid captcha');
        generateCaptcha();
        return;
    }

    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            currentUser = username;
            document.getElementById('loggedInUser').textContent = currentUser;
            document.getElementById('loginSection').style.display = 'none';
            document.getElementById('contentSection').style.display = 'block';
            setCookie('username', username, 30);
            setCookie('password', password, 30);
            listUserFiles();
            listStarredFiles()
        } else {
            alert('Login failed');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Login failed');
    }

    generateCaptcha();
}

async function autoLogin() {
    const username = getCookie('username');
    const password = getCookie('password');

    if (username && password) {
        try {
            const response = await fetch('https://bristle-sideways-blob.glitch.me/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            if (response.ok) {
                currentUser = username;
                document.getElementById('loggedInUser').textContent = currentUser;
                document.getElementById('loginSection').style.display = 'none';
                document.getElementById('contentSection').style.display = 'block';
                listUserFiles();
                listStarredFiles()
            } else {
                alert('Auto-login failed');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Auto-login failed');
        }
    }
}

async function register() {
    document.addEventListener('mousemove', trackMouseMovement);
    const suspicious = analyzeMovements();
    if (suspicious) {
        alert('Suspicious activity detected. Please register again.');
        document.removeEventListener('mousemove', trackMouseMovement);
        return;
    }
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const captchaInput = document.getElementById('captchaInput').value;

    if (captchaInput.toLowerCase() !== captchaText.toLowerCase()) {
        alert('Invalid captcha');
        generateCaptcha();
        return;
    }

    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            alert('Registration successful. Please login.');
        } else {
            alert('Registration failed');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Registration failed');
    }

    generateCaptcha();
}

function logout() {
    currentUser = '';
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('contentSection').style.display = 'none';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('captchaInput').value = '';
    document.getElementById('userFiles').innerHTML = '';
    generateCaptcha();
    deleteCookie('username');
    deleteCookie('password');
}

function deleteCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const description = document.getElementById('fileDescription').value;
    const password = document.getElementById('filePassword').value;

    if (!file) {
        alert('Please select a file');
        return;
    }

    if (!file.name.endsWith('.bin')) {
        alert('Only .bin files are allowed');
        return;
    }

    if (!password) { // Add this check
        alert('Please enter your password');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('description', description);
    formData.append('username', currentUser);
    formData.append('password', password); // Add this line

    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/upload', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.text();
            document.getElementById('uploadResult').innerHTML = `File uploaded successfully. URL: ${result}`;
            listUserFiles();
        } else {
            document.getElementById('uploadResult').innerHTML = 'Upload failed: ' + await response.text();
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('uploadResult').innerHTML = 'Upload failed';
    }
}

async function searchFiles() {
    const searchTerm = document.getElementById('searchInput').value;
    try {
        const response = await fetch(`https://bristle-sideways-blob.glitch.me/search?term=${encodeURIComponent(searchTerm)}&username=${encodeURIComponent(currentUser)}`);
        if (response.ok) {
            const results = await response.json();
            let htmlResult = '<ul>';
            results.forEach(file => {
                const starAction = file.isStarred ? 'unstar' : 'star';
                htmlResult += `<li>
                            <a href="${file.url}" target="_blank">${file.name}</a>
                            <br>Uploaded by: ${file.username}
                            <br>Description: ${file.description}
                            <br>Stars: ${file.starCount}
                            <br><button onclick="toggleStar('${file.name}', '${starAction}')">${file.isStarred ? 'Unstar' : 'Star'}</button>
                        </li>`;
            });
            htmlResult += '</ul>';
            document.getElementById('searchResult').innerHTML = htmlResult;
            openModal();
        } else {
            document.getElementById('searchResult').innerHTML = 'Search failed: ' + await response.text();
            openModal();
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('searchResult').innerHTML = 'Search failed';
        openModal();
    }
}

async function listUserFiles() {
    try {
        const response = await fetch(`https://bristle-sideways-blob.glitch.me/user-files?username=${encodeURIComponent(currentUser)}&currentUser=${encodeURIComponent(currentUser)}`);
        if (response.ok) {
            const files = await response.json();
            let htmlResult = '<ul>';
            files.forEach(file => {
                const starAction = file.isStarred ? 'unstar' : 'star';
                htmlResult += `<li>
                            <a href="${file.url}" target="_blank">${file.name}</a>
                            <br>Description: ${file.description}
                            <br>Stars: ${file.starCount}
                            <br><button onclick="toggleStar('${file.name}', '${starAction}')">${file.isStarred ? 'Unstar' : 'Star'}</button>
                            <br><button onclick="removeFile('${file.name}')">Remove</button>
                        </li>`;
            });
            htmlResult += '</ul>';
            document.getElementById('userFiles').innerHTML = htmlResult;
        } else {
            document.getElementById('userFiles').innerHTML = 'Failed to fetch user files: ' + await response.text();
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('userFiles').innerHTML = 'Failed to fetch user files';
    }
}

async function removeFile(fileName) {
    if (!confirm('Are you sure you want to remove this container, this action cannot be undone?')) {
        return;
    }

    const password = document.getElementById('filePassword').value;
    if (!password) {
        alert('Password is required to remove the file');
        return;
    }

    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: currentUser,
                password: password,
                filename: fileName
            }),
        });

        if (response.ok) {
            alert('File removed successfully');
            listUserFiles();
        } else {
            alert('Failed to remove file: ' + await response.text());
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to remove file');
    }
}

function openModal() {
    document.getElementById('searchModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('searchModal').style.display = 'none';
}

document.querySelector('.close').addEventListener('click', closeModal);

window.onclick = function(event) {
    const modal = document.getElementById('searchModal');
    if (event.target == modal) {
        closeModal();
    }
}

function upload(){
    document.getElementById('uploadSection').style.display = 'block';
    document.getElementById('contentSection').style.display = 'none';
}

function closeUpload(){
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('contentSection').style.display = 'block';
}

window.onload = function() {
    autoLogin();
}

const searchInput = document.getElementById('searchInput');
searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        searchFiles();
    }
});

async function toggleStar(filename, action) {
    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/star', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUser, filename, action }),
        });

        if (response.ok) {
            // Refresh the file list to show updated star status
            listUserFiles();
            // If we're in the search results, refresh those too
            if (document.getElementById('searchModal').style.display === 'block') {
                searchFiles();
            }
        } else {
            alert(`Failed to ${action} file: ` + await response.text());
        }
    } catch (error) {
        console.error('Error:', error);
        alert(`Failed to ${action} file`);
    }
}

async function listStarredFiles() {
    try {
        const response = await fetch(`https://bristle-sideways-blob.glitch.me/starred-files?username=${encodeURIComponent(currentUser)}`);
        if (response.ok) {
            const files = await response.json();
            let htmlResult = '<h3>Starred Files</h3><ul>';
            files.forEach(file => {
                htmlResult += `<li>
                            <a href="${file.url}" target="_blank">${file.name}</a>
                            <br>Uploaded by: ${file.username}
                            <br>Description: ${file.description}
                            <br>Stars: ${file.starCount}
                            <br><button onclick="toggleStar('${file.name}', 'unstar')">Unstar</button>
                        </li>`;
            });
            htmlResult += '</ul>';
            document.getElementById('starredFiles').innerHTML = htmlResult;
        } else {
            document.getElementById('starredFiles').innerHTML = 'Failed to fetch starred files: ' + await response.text();
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('starredFiles').innerHTML = 'Failed to fetch starred files';
    }
}

async function resetPassword() {
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const username = currentUser; // Assuming currentUser is globally accessible

    // Basic client-side validation
    if (!currentPassword || !newPassword || !confirmPassword) {
        alert('Please fill in all fields');
        return;
    }

    if (newPassword !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }

    try {
        const response = await fetch('https://bristle-sideways-blob.glitch.me/reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                current_password: currentPassword,
                new_password: newPassword // Send the new password
            })
        });

        if (response.ok) {
            alert('Password reset successful');
            document.getElementById('passwordResetFor m').reset(); // Reset form fields
        } else {
            const errorMessage = await response.text();
            alert('Password reset failed: ' + errorMessage);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Password reset failed');
    }
}


function reset(){
    document.getElementById('resetSection').style.display = 'block';
    document.getElementById('contentSection').style.display = 'none';
}

function closeReset(){
    document.getElementById('resetSection').style.display = 'none';
    document.getElementById('contentSection').style.display = 'block';
}
