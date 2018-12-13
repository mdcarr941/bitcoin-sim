defmodule BitcoinWeb.BitcoinChannel do
  use Phoenix.Channel

  @doc "No authentication, everyone can join!"
  def join(_topic, _message, socket), do: {:ok, socket}

  @spec channel_callback(term, Bitcoin.NetworkState.t) :: :nosend
  def channel_callback(socket, net_state) do
    chain_lengths = Enum.map(Map.values(net_state.states), fn(node_state) -> length(node_state.chain) end)
    broadcast!(socket, "chain_lengths", %{min: Enum.min(chain_lengths), max: Enum.max(chain_lengths)})
    :nosend
  end

  def handle_in("start_sim", %{"num_nodes" => num_nodes}, socket) when is_integer(num_nodes) and num_nodes > 0 do
    socket = Map.update!(socket, :assigns, fn(assigns) ->
      {_, assigns} = Map.get_and_update(assigns, :network_running, fn(network_running) ->
        if !network_running do
          Bitcoin.Network.start_link(num_nodes)
          Bitcoin.Network.register_callback(:channel_callback, fn(net_state) -> channel_callback(socket, net_state) end)
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
          Bitcoin.Network.stop()
        end
        {network_running, false}
      end)
      assigns
    end)
    {:noreply, socket}
  end
end
