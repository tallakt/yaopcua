defmodule OPCUA.PubSub do
  @moduledoc """
  OPC UA PubSub over UDP with UADP messages (Part 14): values sent cyclically
  from a publisher to any number of subscribers, without sessions, for
  controller-to-controller data.

      # on one PLC
      {:ok, _} = OPCUA.PubSub.Publisher.start_link(
        url: "opc.udp://239.0.0.1:4840", publisher_id: 42, writer_group_id: 1, interval: 50,
        writers: [[id: 1, fields: [{"Speed", :int16}, {"Running", :boolean}], read: fn -> Pump.values() end]])

      # on another
      {:ok, _} = OPCUA.PubSub.Subscriber.start_link(
        url: "opc.udp://239.0.0.1:4840",
        readers: [[publisher_id: 42, writer_group_id: 1, writer_id: 1, fields: [{"Speed", :int16}, {"Running", :boolean}]]])
      # which then gets
      {OPCUA.PubSub, {42, 1}, {:data, %{"Speed" => 1500, "Running" => true}}}

  A multicast address (224.0.0.0 to 239.255.255.255) reaches every
  subscriber on the network; a unicast one reaches one host.

  See `OPCUA.PubSub.UADP` for the message format. Message security is not
  implemented.
  """

  @doc false
  # opc.udp://host:port as an IP address and port.
  def address(url) do
    with %URI{scheme: "opc.udp", host: host, port: port} when is_binary(host) <- URI.parse(url),
         {:ok, ip} <- :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip, port || 4840}
    else
      _ -> {:error, :bad_tcp_endpoint_url_invalid}
    end
  end

  @doc false
  def multicast?({first, _, _, _}), do: first in 224..239

  @doc false
  # Publisher ids as UADP carries them: the smallest integer type that fits.
  def publisher_id({type, value}), do: {type, value}
  def publisher_id(id) when is_binary(id), do: {:string, id}
  def publisher_id(id) when id in 0..0xFF, do: {:byte, id}
  def publisher_id(id) when id in 0..0xFFFF, do: {:uint16, id}
  def publisher_id(id) when id in 0..0xFFFF_FFFF, do: {:uint32, id}
  def publisher_id(id) when id in 0..0xFFFF_FFFF_FFFF_FFFF, do: {:uint64, id}
end
