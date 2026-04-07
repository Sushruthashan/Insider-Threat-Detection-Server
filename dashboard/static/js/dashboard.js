async function loadStats(){

let res = await fetch('/system_stats')
let data = await res.json()

document.getElementById("logins").innerText = data.logins
document.getElementById("files").innerText = data.files
document.getElementById("network").innerText = data.network

}

async function loadAlerts(){

let res = await fetch('/alerts')
let alerts = await res.json()

let table = document.querySelector("#alertsTable tbody")
table.innerHTML = ""

alerts.forEach(a=>{

let row = table.insertRow()

row.insertCell(0).innerText = a[0]
row.insertCell(1).innerText = a[1]
row.insertCell(2).innerText = a[2]
row.insertCell(3).innerText = a[3]
row.insertCell(4).innerText = a[4]

})

}

async function loadRisk(){

let res = await fetch('/risk_scores')
let users = await res.json()

let table = document.querySelector("#riskTable tbody")
table.innerHTML=""

users.forEach(u=>{

let row = table.insertRow()

row.insertCell(0).innerText = u[0]
row.insertCell(1).innerText = u[1]
row.insertCell(2).innerText = u[2]

})

}

async function loadGraph(){

let res = await fetch('/alerts_over_time')
let data = await res.json()

let labels = data.map(x=>x[0])
let values = data.map(x=>x[1])

new Chart(document.getElementById("alertsChart"),{

type:'line',

data:{
labels:labels,
datasets:[{
label:'Alerts',
data:values
}]
}

})

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
    console.log("New log received:", data)

    refreshDashboard()
})
