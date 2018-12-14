// NOTE: The contents of this file will only be executed if
// you uncomment its entry in "assets/js/app.js".

// To use Phoenix channels, the first step is to import Socket,
// and connect at the socket path in "lib/web/endpoint.ex".
//
// Pass the token on params as below. Or remove it
// from the params if you are not using authentication.
import {Socket} from "phoenix"

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

// Now that you are connected, you can join channels with a topic:
let channel = socket.channel("bitcoin:sim", {})

let numNodesInput = document.getElementById("num-nodes-input")
let startBtn = document.getElementById("start-btn")
let stopBtn = document.getElementById("stop-btn")
let display = document.getElementById("display")
let minLengthDiv = document.getElementById("min-length-div")
let maxLengthDiv = document.getElementById("max-length-div")

// Listen for startBtc click.
startBtn.addEventListener("click", event => {
  let numNodes
  if ((numNodes = parseInt(numNodesInput.value)) && numNodes > 0) {
    channel.push("start_sim", {num_nodes: numNodes})
    startBtn.style.display = "none"
    stopBtn.style.display = "block"
    minLengthDiv.innerText = ""
    maxLengthDiv.innerText = ""
    display.style.display = "block"
  }
})

// Listen for stopBtc click.
stopBtn.addEventListener("click", event => {
  channel.push("stop_sim")
  stopBtn.style.display = "none"
  startBtn.style.display = "block"
  display.style.display = "none"
})

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

channel.on("node_cash", payload => {
  let totalBtc = 0, btc = 0 
  const labels = []
  const data = []
  for (let key in payload) {
    if (payload.hasOwnProperty(key)) {
      let match
      if (match = pidRgx.exec(key)) {
        labels.push(match[1])
      } else {
        labels.push("???")
      }
      btc = payload[key]/100000000
      totalBtc += btc
      data.push(btc)
    }
  }
  nodeCashChart.data.labels = labels
  nodeCashChart.data.datasets[0].data = data
  nodeCashChart.data.datasets[0].backgroundColor = new Array(data.length).fill(backgroundColor)
  nodeCashChart.data.datasets[0].boarderColor = new Array(data.length).fill(boarderColor)
  nodeCashChart.update()

  totalBtcDiv.innerText = totalBtc
})

channel.join()
  .receive("ok", resp => { console.log("Joined successfully", resp) })
  .receive("error", resp => { console.log("Unable to join", resp) })

export default socket
