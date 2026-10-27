defmodule OPCUA.PubSubSecureInteropTest do
  # Encrypted PubSub against open62541, an independent implementation of
  # Part 14, through test/support/open62541_pubsub_peer.c in a process of its
  # own. Runs where open62541 is built with the PubSub AES-CTR policies; see
  # test_helper.exs. Keys are fixed: open62541 1.5 has no usable key service.
  use ExUnit.Case, async: false

  @moduletag :open62541_pubsub_secure
  @moduletag timeout: 120_000

  alias OPCUA.PubSub.{Publisher, Security, Subscriber}

  @fields [{"Counter", :int32}, {"Wave", :double}]

  setup_all do
    {:ok, peer} = OPCUA.Open62541.build_pubsub_peer()
    %{peer: peer}
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0)
    {:ok, port} = :inet.port(socket)
    :gen_udp.close(socket)
    port
  end

  defp run(peer, args) do
    port =
      Port.open({:spawn_executable, peer}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: args
      ])

    port
  end

  defp output(port, acc \\ "") do
    receive do
      {^port, {:data, data}} -> output(port, acc <> data)
      {^port, {:exit_status, _}} -> acc
    after
      15_000 -> acc
    end
  end

  for {policy, bits} <- [aes128_ctr: 128, aes256_ctr: 256],
      {mode, word} <- [sign: "sign", sign_and_encrypt: "encrypt"] do
    describe "#{policy} #{mode}" do
      test "open62541 reads what yaopcua publishes", %{peer: peer} do
        material = Security.generate(unquote(policy))
        url = "opc.udp://127.0.0.1:#{free_udp_port()}"

        start_supervised!(
          {Publisher,
           url: url,
           publisher_id: 2234,
           writer_group_id: 100,
           interval: 50,
           security: [mode: unquote(mode), policy: unquote(policy), keys: [{1, material}]],
           writers: [
             [id: 62541, fields: @fields, read: fn -> %{"Counter" => 7, "Wave" => 0.5} end]
           ]}
        )

        port =
          run(peer, [
            "subscribe",
            url,
            Base.encode16(material, case: :lower),
            "#{unquote(bits)}",
            unquote(word),
            "3"
          ])

        assert output(port) =~ "value 7 0.500000"
      end

      test "yaopcua reads what open62541 publishes", %{peer: peer} do
        material = Security.generate(unquote(policy))
        url = "opc.udp://239.0.0.9:#{free_udp_port()}"

        start_supervised!(
          {Subscriber,
           to: self(),
           url: url,
           security: [mode: unquote(mode), policy: unquote(policy), keys: [{1, material}]],
           readers: [
             [
               publisher_id: 2234,
               writer_group_id: 100,
               writer_id: 62541,
               fields: @fields,
               timeout: 2000
             ]
           ]}
        )

        port =
          run(peer, [
            "publish",
            url,
            Base.encode16(material, case: :lower),
            "#{unquote(bits)}",
            unquote(word),
            "3"
          ])

        assert_receive {OPCUA.PubSub, _, {:data, %{"Counter" => counter, "Wave" => wave}}}, 5000
        assert is_integer(counter) and is_float(wave)
        _ = output(port)
      end

      test "open62541 rejects what is signed with other keys", %{peer: peer} do
        material = Security.generate(unquote(policy))
        url = "opc.udp://127.0.0.1:#{free_udp_port()}"

        start_supervised!(
          {Publisher,
           url: url,
           publisher_id: 2234,
           writer_group_id: 100,
           interval: 50,
           security: [mode: unquote(mode), policy: unquote(policy), keys: [{1, material}]],
           writers: [
             [id: 62541, fields: @fields, read: fn -> %{"Counter" => 7, "Wave" => 0.5} end]
           ]}
        )

        other = Base.encode16(Security.generate(unquote(policy)), case: :lower)

        port = run(peer, ["subscribe", url, other, "#{unquote(bits)}", unquote(word), "3"])
        refute output(port) =~ "value 7"
      end
    end
  end
end
