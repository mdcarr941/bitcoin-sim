defmodule BitcoinWeb.BitcoinChannel do
  use Phoenix.Channel
  alias Bitcoin.Network
  alias Bitcoin.Crypto
  alias Bitcoin.BtcNode
  alias Bitcoin.Serialize

  @doc "No authentication, everyone can join!"
  def join(_topic, _message, socket), do: {:ok, socket}

  @spec chain_length_callback(term, NetworkState.t) :: :nosend
  def chain_length_callback(socket, net_state) do
    chain_lengths = Enum.map(Map.values(net_state.states), fn(node_state) -> length(node_state.chain) end)
    broadcast!(socket, "chain_lengths", %{min: Enum.min(chain_lengths), max: Enum.max(chain_lengths)})
    :nosend
  end

  @doc "Broadcast the amount of cash each node has."
  @spec cash_callback(term, NetworkState.t) :: :nosend
  def cash_callback(socket, net_state) do
    node_cash = Enum.reduce(net_state.states, %{}, fn({node_pid, node_state}, node_cash) ->
      cash = Map.get(node_state.cash_index, Crypto.hash160(node_state.pub_key), 0)
      Map.put(node_cash, inspect(node_pid), cash)
    end)
    broadcast!(socket, "node_cash", node_cash)
    :nosend
  end

  @spec pid_from_string(String.t) :: pid
  def pid_from_string("#PID" <> string) do
    :erlang.binary_to_list(string) |> :erlang.list_to_pid
  end

  def handle_in("start_sim", %{"num_nodes" => num_nodes}, socket) when is_integer(num_nodes) and num_nodes > 0 do
    socket = Map.update!(socket, :assigns, fn(assigns) ->
      {_, assigns} = Map.get_and_update(assigns, :network_running, fn(network_running) ->
        if !network_running do
          Network.start_link(num_nodes)
          Network.register_callback(:chain_length_callback, fn(net_state) -> chain_length_callback(socket, net_state) end)
          Network.register_callback(:cash_callback, fn(net_state) -> cash_callback(socket, net_state) end)
        end
        {network_running, true}
      end)
      assigns
    end)
    {:noreply, socket}
  end

  def handle_in("stop_sim", _payload, socket) do
    socket = Map.update!(socket, :assigns, fn(assigns) ->
      {_, assigns} = Map.get_and_update(assigns, :network_running, fn(network_running) ->
        if network_running do
          Network.stop()
        end
        {network_running, false}
      end)
      assigns
    end)
    {:noreply, socket}
  end

  def handle_in("get_priv_key", %{"node_pid" => node_pid}, socket) do
    if Map.get(socket.assigns, :network_running) do
      pid = pid_from_string(node_pid)
      node_state = BtcNode.get_state(pid)
      {:reply, {:ok, %{"priv_key" => Serialize.to_hex(node_state.priv_key)}}, socket}
    else
      {:reply, :not_running, socket}
    end
  end

  def handle_in("stop_mining", _payload, socket) do
    if Map.get(socket.assigns, :network_running) do
      Network.stop_mining()
    end
    {:noreply, socket}
  end

  def handle_in("start_mining", _payload, socket) do
    if Map.get(socket.assigns, :network_running) do
      Network.start_mining()
    end
    {:noreply, socket}
  end

  # def handle_in("get_signing_input", payload, socket) do
  #   if Map.get(socket.assigns, :network_running) do
  #     {:reply, Network.get_signing_input(payload), socket}
  #   else
  #     {:reply, :not_running, socket}
  #   end
  # end
end
