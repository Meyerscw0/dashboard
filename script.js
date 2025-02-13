// PASSWORD STRENGTH CHECKER
function checkPassword() {
    const password = document.getElementById("password").value;
    const strengthText = document.getElementById("password-strength");

    let strength = 0;

    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    const strengthLevels = ["Weak ❌", "At risk ⚠️", "Good ✅", "Strong 💪", "Very Strong 🔥"];
    strengthText.innerHTML = `<strong>Strength:</strong> ${strengthLevels[strength] || "Very Weak ❌"}`;
}

// AES ENCRYPTION TOOL
async function encryptText() {
    const plaintext = document.getElementById("plaintext").value;
    if (!plaintext) return;

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

    // Convert encrypted data to base64 for display
    const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));

    document.getElementById("encrypted-text").textContent = encryptedBase64;
    document.getElementById("decrypted-text").textContent = ""; // Clear previous result

    // Store key and IV for decryption
    window.encryptionKey = key;
    window.encryptionIv = iv;
}

async function decryptText() {
    if (!window.encryptionKey || !window.encryptionIv) {
        alert("No encrypted data found. Please encrypt something first.");
        return;
    }

    const encryptedBase64 = document.getElementById("encrypted-text").textContent;
    if (!encryptedBase64) return;

    const encryptedBytes = new Uint8Array(atob(encryptedBase64).split("").map(c => c.charCodeAt(0)));

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: window.encryptionIv },
        window.encryptionKey,
        encryptedBytes
    );

    const decoder = new TextDecoder();
    document.getElementById("decrypted-text").textContent = decoder.decode(decrypted);
}

// FETCH CYBERSECURITY NEWS
async function fetchCybersecurityNews() {
    const newsList = document.getElementById("news-list");
    newsList.innerHTML = "<li>Loading...</li>";

    try {
        const response = await fetch("https://newsapi.org/v2/everything?q=cybersecurity&apiKey=c2616b9d6da94762906e67458e6579ad");
        const data = await response.json();

        newsList.innerHTML = ""; // Clear loading message
        data.articles.slice(0, 5).forEach(article => {
            const listItem = document.createElement("li");
            listItem.innerHTML = `<a href="${article.url}" target="_blank">${article.title}</a>`;
            newsList.appendChild(listItem);
        });
    } catch (error) {
        newsList.innerHTML = "<li>Failed to load news. Check API key.</li>";
    }
}

// Automatically fetch news on page load
fetchCybersecurityNews();
