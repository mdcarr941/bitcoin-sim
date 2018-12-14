// NOTE: The contents of this file will only be executed if
// you uncomment its entry in "assets/js/app.js".

// To use Phoenix channels, the first step is to import Socket,
// and connect at the socket path in "lib/web/endpoint.ex".
//
// Pass the token on params as below. Or remove it
// from the params if you are not using authentication.
import {Socket} from "phoenix"
// Import the elliptic pacakge so we can do ECDSA.
import ellipticjs from '../node_modules/elliptic'

let socket = new Socket("/socket", {params: {token: window.userToken}})

// When you connect, you'll often need to authenticate the client.
// For example, imagine you have an authentication plug, `MyAuth`,
// which authenticates the session and assigns a `:current_user`.
// If the current user exists you can assign the user's token in
// the connection for use in the layout.
//
// In your "lib/web/router.ex":
//
//     pipeline :browser do
//       ...
//       plug MyAuth
//       plug :put_user_token
//     end
//
//     defp put_user_token(conn, _) do
//       if current_user = conn.assigns[:current_user] do
//         token = Phoenix.Token.sign(conn, "user socket", current_user.id)
//         assign(conn, :user_token, token)
//       else
//         conn
//       end
//     end
//
// Now you need to pass this token to JavaScript. You can do so
// inside a script tag in "lib/web/templates/layout/app.html.eex":
//
//     <script>window.userToken = "<%= assigns[:user_token] %>";</script>
//
// You will need to verify the user token in the "connect/3" function
// in "lib/web/channels/user_socket.ex":
//
//     def connect(%{"token" => token}, socket, _connect_info) do
//       # max_age: 1209600 is equivalent to two weeks in seconds
//       case Phoenix.Token.verify(socket, "user socket", token, max_age: 1209600) do
//         {:ok, user_id} ->
//           {:ok, assign(socket, :user, user_id)}
//         {:error, reason} ->
//           :error
//       end
//     end
//
// Finally, connect to the socket:
socket.connect()

// Join the bitcoin:sim topic.
let channel = socket.channel("bitcoin:sim", {})

const numNodesInput = document.getElementById("num-nodes-input")
const startBtn = document.getElementById("start-btn")
const stopBtn = document.getElementById("stop-btn")
const display = document.getElementById("display")

// Listen for startBtc click.
startBtn.addEventListener("click", event => {
  let numNodes
  if ((numNodes = parseInt(numNodesInput.value)) && numNodes > 0) {
    channel.push("start_sim", {num_nodes: numNodes})
    startBtn.style.display = "none"
    stopBtn.style.display = "inline"
    display.style.display = "block"
  }
})

// Remove all children of a node.
function removeAllChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild)
  }
}

let nodePidSelectInitialized = false

// Listen for stopBtc click.
stopBtn.addEventListener("click", event => {
  channel.push("stop_sim")
  stopBtn.style.display = "none"
  startBtn.style.display = "inline"
  display.style.display = "none"
  removeAllChildren(nodePidsSelect)
  nodePidSelectInitialized = false
})

// Update on chain_length message.
let minLengthDiv = document.getElementById("min-length-div")
let maxLengthDiv = document.getElementById("max-length-div")
channel.on("chain_lengths", payload => {
  minLengthDiv.innerText = payload.min
  maxLengthDiv.innerText = payload.max
})

const backgroundColor = "rgb(255, 126, 0, 0.5)"
const boarderColor = "rgb(255, 126, 0, 0.5)"

const nodeCashChart = new Chart(document.getElementById("node-cash-chart"), {
  type: "radar",
  data: {
    labels: [],
    datasets: [{
      label: "Bitcoins",
      data: [],
      borderWidth: 1
    }]
  },
  options: {
    // scales: {
    //   xAxes: [{
    //     scaleLabel: {
    //       display: true,
    //       labelString: "Node PID"
    //     }
    //   }],
    //   yAxes: [{
    //     ticks: {
    //       beginAtZero: true
    //     },
    //     scaleLabel: {
    //       display: true,
    //       labelString: "BTC"
    //     }
    //   }]
    // },
    tooltips: false
  }
})

const pidRgx = /<([\d\.]+)>/
const totalBtcDiv = document.getElementById("total-btc-div")
const nodePidsSelect = document.getElementById("node-pids")

channel.on("node_cash", payload => {
  let totalBtc = 0, btc = 0, option
  const labels = [], data = []
  for (let key in payload) {
    if (payload.hasOwnProperty(key)) {
      let match, keyDisplay
      if (match = pidRgx.exec(key)) {
        keyDisplay = match[1]
      } else {
        keyDisplay = key
      }
      labels.push(keyDisplay)

      btc = payload[key]/100000000
      totalBtc += btc
      data.push(btc)

      // Fill the node pid select element if it doesn't have any elements in it.
      if (!nodePidSelectInitialized) {
        option = document.createElement("option")
        option.value = key
        option.innerText = keyDisplay
        nodePidsSelect.appendChild(option)
      }
    }
  }
  nodePidSelectInitialized = true
  nodeCashChart.data.labels = labels
  nodeCashChart.data.datasets[0].data = data
  nodeCashChart.data.datasets[0].backgroundColor = new Array(data.length).fill(backgroundColor)
  nodeCashChart.data.datasets[0].boarderColor = new Array(data.length).fill(boarderColor)
  nodeCashChart.update()

  totalBtcDiv.innerText = totalBtc
})

// The pause and resume buttons.
const pauseBtn = document.getElementById("pause-btn")
const resumeBtn = document.getElementById("resume-btn")
pauseBtn.addEventListener("click", event => {
  channel.push("stop_mining")
  pauseBtn.style.display = "none"
  resumeBtn.style.display = "inline"
})
resumeBtn.addEventListener("click", event => {
  channel.push("start_mining")
  resumeBtn.style.display = "none"
  pauseBtn.style.display = "inline"
})

// Do transaction signing.
const ec = new ellipticjs.ec('secp256k1');
const currentPrivKeyNodeDiv = document.getElementById("current-priv-key-node")

// The get private key button.
let privKey, privKeyPid
document.getElementById("get-priv-key-btn").addEventListener("click", event => {
  privKeyPid = nodePidsSelect.value
  channel.push("get_priv_key", {"node_pid": privKeyPid})
    .receive("ok", privKeyHex => {
      console.log("privKeyHex is", privKeyHex)
      privKey = ec.keyPair(privKeyHex)
      currentPrivKeyNodeDiv.innerText = privKeyPid
    })
})

const sendAmountInput = document.getElementById("send-amount")
// document.getElementById("send-btc-btn").addEventListener("click", event => {
//   let amount = sendAmountInput.value, nodePid = nodePidsSelect.value
//   channel.push("get_signing_input", {"amount": amount, "pid_to": nodePid, "pid_from": privKeyPid})
//     .receive("ok", resp => {
//       // do signing
//       // send signed transaction to server
//     })
// })

channel.join()
  .receive("ok", resp => { console.log("Joined successfully", resp) })
  .receive("error", resp => { console.log("Unable to join", resp) })

export default socket
