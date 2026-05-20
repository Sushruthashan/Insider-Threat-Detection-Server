async function loadStats(){

let res = await fetch('/system_stats')
let data = await res.json()

document.getElementById("logins").innerText = data.logins
document.getElementById("files").innerText = data.files
document.getElementById("network").innerText = data.network

}

async function loadRisk(){
    let res = await fetch('/risk_scores');
    let users = await res.json();

    let table = document.querySelector("#riskTable tbody");
    table.innerHTML = "";

    users.forEach(u => {
    let row = table.insertRow();
    row.insertCell(0).innerText = u.username;
    
    let scoreCell = row.insertCell(1);
    scoreCell.innerText = u.risk_score;

    if (u.risk_score > 10) scoreCell.style.color = "#e74c3c";
    else if (u.risk_score > 5) scoreCell.style.color = "#f1c40f";
    else scoreCell.style.color = "#27ae60";
    
    if (a[4] === "HIGH") {
    row.style.backgroundColor = "#fff5f5";
    }
   
});
}

// In loadAlerts, make sure you match the number of columns in your HTML
async function loadAlerts(){
    let res = await fetch('/alerts');
    let alerts = await res.json();
    let table = document.querySelector("#alertsTable tbody");
    table.innerHTML = "";

    alerts.forEach(a => {
    let row = table.insertRow();
    row.insertCell(0).innerText = a[0]; // User
    row.insertCell(1).innerText = a[1]; // Type
    row.insertCell(2).innerText = a[2]; // Details 
    row.insertCell(3).innerText = a[3]; // Score
    
    let sevCell = row.insertCell(4);
    sevCell.innerText = a[4]; // Severity
    sevCell.className = "sev-" + a[4]; // Adds class sev-HIGH, sev-MEDIUM, etc.

    row.insertCell(5).innerText = a[5]; // Time
});
}

let chartInstance = null;

async function loadGraph(){

    let res = await fetch('/alerts_over_time');
    let data = await res.json();

    let labels = data.map(x => x[0]);
    let values = data.map(x => x[1]);

    if (chartInstance) {
        chartInstance.destroy();
    }

    chartInstance = new Chart(document.getElementById("alertsChart"), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alerts',
                data: values
            }]
        }
    });
}

function refreshDashboard(){

loadStats()
loadAlerts()
loadRisk()
loadGraph()

}

refreshDashboard()

const socket = io()

socket.on('new_log', function(data){
    console.log("New log:", data);

    loadAlerts();   // only refresh alerts
    loadStats();    // lightweight update
});

// =========================
// ANOMALY MODAL
// =========================

const modal = document.getElementById("anomalyModal");
const btn = document.getElementById("anomalyBtn");
const closeBtn = document.querySelector(".close-btn");

btn.onclick = () => {
    modal.style.display = "block";
};

closeBtn.onclick = () => {
    modal.style.display = "none";
};

window.onclick = (e) => {
    if (e.target == modal) {
        modal.style.display = "none";
    }
};

// =========================
// ANOMALY DETAILS
// =========================

function showAnomalyDetails(type){

    const details = document.getElementById("anomalyDetails");

    const anomalyData = {

        login: `
            <h3>Login Time Anomaly</h3>
            <p>Detects logins occurring far outside the user's baseline login hour.</p>

            <b>Condition:</b>
            <p>Deviation > 3 hours from baseline</p>

            <b>Risk:</b>
            <p>May indicate compromised credentials or unusual employee behavior.</p>
        `,

        file: `
            <h3>High File Access Rate</h3>

            <p>Detects unusually high file activity within a short period.</p>

            <b>Condition:</b>
            <p>Recent file count > adaptive threshold</p>

            <b>Risk:</b>
            <p>Possible bulk data theft or insider exfiltration.</p>
        `,

        login_spike: `
            <h3>Login Frequency Spike</h3>

            <p>Detects repeated login events within a short timeframe.</p>

            <b>Condition:</b>
            <p> 5 logins in 5 minutes</p>

            <b>Risk:</b>
            <p>Possible brute-force attempt or credential misuse.</p>
        `,

        offhours: `
            <h3>Off-Hours Login</h3>

            <p>Detects logins during unusual working hours.</p>

            <b>Condition:</b>
            <p>Login before 6 AM or after 10 PM</p>

            <b>Risk:</b>
            <p>Possible unauthorized remote access.</p>
        `,

        sensitive: `
            <h3>Sensitive File Access</h3>

            <p>Detects access to confidential files.</p>

            <b>Keywords:</b>
            <p>password, confidential, secret, admin, .env</p>

            <b>Risk:</b>
            <p>Potential insider data theft.</p>
        `,

        postlogin: `
            <h3>Post-Login File Surge</h3>

            <p>Detects large file activity immediately after login.</p>

            <b>Condition:</b>
            <p>> 10 files after login session</p>

            <b>Risk:</b>
            <p>Possible rapid data collection after access acquisition.</p>
        `,

        mouse: `
            <h3>Suspicious Mouse Activity</h3>

            <p>Detects automated/scripted user interaction patterns.</p>

            <b>Conditions:</b>

            <p>
High clicks
Low movement
Automation-like interaction
            </p>

            <b>Risk:</b>
            <p>Possible macro/script/bot activity.</p>
        `
    };

    details.innerHTML = anomalyData[type];
}
