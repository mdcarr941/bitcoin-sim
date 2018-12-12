defmodule BitcoinWeb.BitcoinChannel do
  use Phoenix.Channel

  @doc "No authentication, everyone can join!"
  def join(_topic, _message, socket), do: {:ok, socket}

  def handle_in("start_sim", %{"num_nodes" => num_nodes}, socket) when is_integer(num_nodes) and num_nodes > 0 do
    socket = Map.update!(socket, :assigns, fn(assigns) ->
      {_, assigns} = Map.get_and_update(assigns, :network_running, fn(network_running) ->
        if !network_running do
          Bitcoin.Network.start_link(num_nodes)
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
