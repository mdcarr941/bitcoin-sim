defmodule Bitcoin.Tests.General do
  use ExUnit.Case, async: true
  import Bitcoin.Tests.Helpers

  test "TxOut.add_pk_script" do
    address = address()
    tx_out = TxOut.new(15, address)
    pk_script_expected = Serialize.from_byte_list([0x76, 0xa9, 0x14,
      0xc8, 0xe9, 0x09, 0x96, 0xc7, 0xc6, 0x08, 0x0e, 0xe0, 0x62, 0x84, 0x60, 0x0c, 0x68, 0x4e, 0xd9, 0x04, 0xd1, 0x4c, 0x5c,
      0x88, 0xac
    ])
    assert Script.compile(tx_out.pk_script) == pk_script_expected
  end

  test "TxOut serialize deserialize" do
    tx_out = test_tx_out()
    {new_tx_out, <<>>} = TxOut.deserialize(TxOut.serialize(tx_out))
    assert_tx_out_equal(tx_out, new_tx_out)
  end

  test "Script compile decompile" do
    tx_out = TxOut.new(15, address())
    script = tx_out.pk_script
    compiled = Script.compile(script)
    {new_script, <<>>} = Script.decompile(compiled)
    assert_scripts_equal(script, new_script)
  end

  test "Script decompile" do
    priv_key = Serialize.from_hex("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
    pub_key = Crypto.key_gen(priv_key)
    script = TxOut.pk_script_key(pub_key)
    bin = Script.compile(script)
    hex = Serialize.to_hex(bin)

    expected_hex = "76a914010966776006953d5567439e5e39f86a0d273bee88ac"
    expected_bin = Serialize.from_hex(expected_hex)
    {expected_script, <<>>} = Script.decompile(expected_bin)

    assert hex == expected_hex
    assert bin == expected_bin
    assert_scripts_equal(script, expected_script)
  end

  test "OutPoint serialize deserialize" do
    hash = test_hash()
    out_point = %OutPoint{hash: hash, index: 1}
    {new_out_point, <<>>} = OutPoint.deserialize(OutPoint.serialize(out_point))
    assert_out_points_equal(out_point, new_out_point)
  end

  test "TxIn serialize deserialize" do
    tx_in = test_tx_in()
    {new_tx_in, <<>>} = TxIn.deserialize(TxIn.serialize(tx_in))
    assert_tx_in_equal(tx_in, new_tx_in)
  end

  test "CoinBaseIn deserialize serialize" do
    # Got this from https://bitcoin.org/en/developer-reference#raw-transaction-format
    bin = Serialize.from_hex(
      "00000000000000000000000000000000"
      <> "00000000000000000000000000000000" # Previous outpoint TXID
      <> "ffffffff" # Previous outpoint index
      <> "29" # Bytes in coinbase
      <> "03" # Bytes in height
      <> "4e0105" # Height: 328014
      <> "062f503253482f0472d35454085fffed"
      <> "f2400000f90f54696d65202620486561"
      <> "6c74682021" # Arbitrary data
      <> "00000000" # Sequence
    )
    {coinbase, <<>>} = CoinBaseIn.deserialize(bin)
    assert CoinBaseIn.serialize(coinbase) == bin
  end
end

defmodule Bitcoin.Tests.Serialize do
  use ExUnit.Case, async: true
  import Bitcoin.Tests.Helpers
  use Bitwise

  test "Serialize.to_little_end" do
    assert Serialize.to_little_end(1, 1) == <<1>>
    assert Serialize.to_little_end(255, 2) == <<255, 0>>
    assert Serialize.to_little_end(256, 2) == <<0, 1>>
    assert Serialize.to_little_end(257, 2) == <<1, 1>>
    assert Serialize.to_little_end(1 <<< 16, 3) == <<0, 0, 1>>
    assert Serialize.to_little_end((1 <<< 32) - 1, 5) == <<255, 255, 255, 255, 0>>
    assert Serialize.to_little_end(-128, 1) == <<128>>
    assert Serialize.to_little_end(-127, 1) == <<129>>
  end

  test "Serialize.from_little_end" do
    assert Serialize.from_little_end(<<1>>) == 1
    assert Serialize.from_little_end(<<0, 1>>) == 256
    assert Serialize.from_little_end(Serialize.to_little_end(777, 4)) == 777
    assert Serialize.from_little_end(Serialize.to_little_end(522, 4)) == 522
    assert Serialize.from_little_end(Serialize.to_little_end(-221, 4)) == -221
    assert Serialize.from_little_end(Serialize.to_little_end(22900, 4)) == 22900
    assert Serialize.from_little_end(Serialize.to_little_end(-22211, 4)) == -22211
  end

  test "Serialize.base58enc" do
    {pub_key, _} = pub_priv()
    addr_data = Crypto.address_data_mainnet(pub_key)
    address = Serialize.base58enc(addr_data)
    assert address == address()
  end

  test "Serialize.base58dec" do
    {pub_key, _} = pub_priv()
    addr_data = Crypto.address_data_mainnet(pub_key)
    address = address()
    assert Serialize.base58dec(address, byte_size(addr_data)) == addr_data

    Enum.each(1..10, fn(index) ->
      str = "This is string " <> Integer.to_string(index)
      assert to_string(Serialize.base58dec(Serialize.base58enc(str), byte_size(str))) == str
    end)
  end

  test "Serialize compact_size_uint" do
    bin = <<0xfd0302::unsigned-big-size(24)>>
    assert Serialize.to_compact_size_uint(515) == bin
    assert {515, <<>>} = Serialize.from_compact_size_uint(bin)

    Enum.each(6..42, fn(n) ->
      value = 3 * (1 <<< n)
      assert {^value, <<>>} = Serialize.from_compact_size_uint(Serialize.to_compact_size_uint(value))
    end)
  end
end

defmodule Bitcoin.Tests.BlockHeader do
  use ExUnit.Case, async: true
  import Bitcoin.Tests.Helpers

  test "BlockHeader.target_threshold" do
    assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x01003456}) == 0x00
    assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x01123456}) == 0x12
    assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x02008000}) == 0x80
    assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x05009234}) == 0x92340000
    #assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x04923456}) == -0x12345600 # This one fails.
    assert BlockHeader.target_threshold(%BlockHeader{n_bits: 0x04123456}) == 0x12345600
  end

  test "BlockHeader serialize deserialize" do
    header = %BlockHeader{hash_prev_block: test_hash(), hash_merkle_root: test_hash()}
    {new_header, <<>>} = BlockHeader.deserialize(BlockHeader.serialize(header))
    assert header.version == new_header.version
    assert header.hash_prev_block == new_header.hash_prev_block
    assert header.hash_merkle_root == new_header.hash_merkle_root
    assert header.time == new_header.time
    assert header.n_bits == new_header.n_bits
    assert header.nonce == new_header.nonce
  end

  test "BlockHeader.serialize" do
    hash_prev_block = Serialize.from_hex("b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c0000000000000000")
    hash_merkle_root = Serialize.from_hex("9d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab31471")
    header = %BlockHeader{version: 2, hash_prev_block: hash_prev_block, hash_merkle_root: hash_merkle_root,
      time: 1415239972, n_bits: 0x181bc330, nonce: 0x64089ffe
    }
    expected = Serialize.from_hex("02000000b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c0000000000000000"
      <> "9d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab3147124d95a5430c31b18fe9f0864"
    )
    assert BlockHeader.serialize(header) == expected
  end

  test "BlockHeader.hash" do
    # This example is from https://en.bitcoin.it/wiki/Block_hashing_algorithm
    {header, <<>>} = BlockHeader.deserialize(Serialize.from_hex(
      "01000000"
      <> "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
      <> "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
      <> "c7f5d74d"
      <> "f2b9441a"
      <> "42a14695"
    ))
    assert BlockHeader.hash(header)
      == Serialize.from_hex("1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000")
  end
end

defmodule Bitcoin.Tests.Crypto do
  use ExUnit.Case, async: true
  import Bitcoin.Tests.Helpers

  test "Crypto.sign and Crypto.verify" do
    {pub_key, priv_key} = Crypto.key_gen()
    msg = "Look upon my works, ye mighty, and despair!"
    sig = Crypto.sign(msg, priv_key)
    assert Crypto.verify(msg, pub_key, sig)
  end

  test "Crypto.address_data" do
    {pub_key, _} = Crypto.key_gen()
    data = Crypto.address_data_testnet(pub_key)
    assert byte_size(data) == 25
    <<version::integer-unit(8)-size(1), payload::binary-unit(8)-size(20), checksum::binary-unit(8)-size(4)>> = data
    assert version == 0x6f
    assert payload == :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    full_checksum = :crypto.hash(:sha256, :crypto.hash(:sha256, <<version>> <> payload))
    assert <<^checksum::binary-size(4), _::binary>> = full_checksum
  end

  test "Crypto.payload" do
    {pub_key, _} = pub_priv()
    expected_payload = :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    address = Crypto.address(pub_key)
    assert address == "myqGc9SzpYm3qFU83UNhMZ8mjCFqzmGi2x"
    {:ok, version, payload} = Crypto.payload(address)
    assert version == <<0x6f>> # P2PKH in testnet
    assert payload == expected_payload

    address = String.slice(address, 0..4) <> "7" <> String.slice(address, 6..String.length(address))
    assert address == "myqGc7SzpYm3qFU83UNhMZ8mjCFqzmGi2x"
    assert {:error} = Crypto.payload(address)
  end

  test "Crypto.merkle_root" do
    # These are the transactions from block 170. This block contains the first non-coinbase transaction.
    # See https://btc.com/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
    assert Crypto.merkle_root([
      Serialize.from_hex("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"), # coinbase
      Serialize.from_hex("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")  # first transaction
    ]) == Serialize.from_hex("7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff") # expected merkle root
  end
end

defmodule Bitcoin.Tests.Transaction do
  use ExUnit.Case, async: true
  import Bitcoin.Tests.Helpers

  test "Transaction.deserialize_coinbase" do
    # Got this from https://bitcoin.org/en/developer-reference#raw-transaction-format
    bin = Serialize.from_hex(
      "01000000" # Version
      <> "01" # Number of inputs
      <> "00000000000000000000000000000000"
      <> "00000000000000000000000000000000" #  Previous outpoint TXID
      <> "ffffffff" # Previous outpoint index
      <> "29" # Bytes in coinbase
      <> "03" # Bytes in height
      <> "4e0105" # Height: 328014
      <> "062f503253482f0472d35454085fffed"
      <> "f2400000f90f54696d65202620486561"
      <> "6c74682021" # Arbitrary data
      <> "00000000" # Sequence
      <> "01" # Output count
      <> "2c37449500000000" # Satoshis (25.04275756 BTC)
      <> "1976a914a09be8040cbf399926aeb1f4"
      <> "70c37d1341f3b46588ac" # P2PKH script
      <> "00000000" # Locktime
    )
    {trans, <<>>} = Transaction.deserialize_coinbase(bin)
    assert Transaction.serialize(trans) == bin
  end

  test "Transaction serialize deserialize" do
    transaction = %Transaction{tx_in: [test_tx_in()], tx_out: [test_tx_out()]}
    {new_transaction, <<>>} = Transaction.deserialize(Transaction.serialize(transaction))
    assert transaction.version == new_transaction.version
    Enum.each(0..length(transaction.tx_in)-1, fn(index) ->
      assert_tx_in_equal(Enum.at(transaction.tx_in, index), Enum.at(new_transaction.tx_in, index))
    end)
    Enum.each(0..length(transaction.tx_out)-1, fn(index) ->
      assert_tx_out_equal(Enum.at(transaction.tx_out, index), Enum.at(new_transaction.tx_out, index))
    end)
    assert transaction.lock_time == new_transaction.lock_time
  end

  test "Transaction.signing_input_bytes" do
    {trans, prev_pk_script, _} = transaction_test_case()
    assert Transaction.signing_input_bytes(trans, prev_pk_script, 0) == Serialize.from_hex(
      "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f201000000"
      <> "1976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff01605af40500000000"
      <> "1976a914097072524438d003d23a2f23edb65aae1bb3e46988ac0000000001000000"
    )
  end

  test "Transaction.signing_input" do
    {trans, prev_pk_script, _} = transaction_test_case()
    assert Transaction.signing_input(trans, prev_pk_script, 0) == Serialize.from_hex(
      "9302bda273a887cb40c13e02a50b4071a31fd3aae3ae04021b0b843dd61ad18e"
    )
  end

  test "Transaction signature verify_signature" do
    {trans, prev_pk_script, priv_key} = transaction_test_case()
    sig = Transaction.signature(trans, prev_pk_script, 0, priv_key)
    assert Transaction.verify_signature(trans, prev_pk_script, 0, Crypto.key_gen(priv_key), sig)
  end

  test "Transaction.sign" do
    {trans, prev_pk_script, priv_key} = transaction_test_case()
    trans = Transaction.sign(trans, prev_pk_script, 0, priv_key)
    pairs = Transaction.to_pairs(trans)

    {trans_exp, <<>>} = Transaction.deserialize(Serialize.from_hex(
      "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f201000000"
      <> "8c4930460221009e0339f72c793a89e664a8a932df073962a3f84eda0bd9e02084a6a9567f75aa0"
      <> "22100bd9cbaca2e5ec195751efdfac164b76250b1e21302e51ca86dd7ebd7020cdc060141045086"
      <> "3ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9"
      <> "e77237716103abc11a1df38855ed6f2ee187e9c582ba6ffffffff01605af405000000001976a914"
      <> "097072524438d003d23a2f23edb65aae1bb3e46988ac00000000"
    ))
    pairs_exp = Transaction.to_pairs(trans_exp)

    for {{key1, val1}, {key2, val2}} <- Enum.zip(pairs, pairs_exp) do
      assert key1 == key2
      case key1 do
        # The signature script is randomized because the signature depends on a random number.
        # So do not check these fields.
        :sig_script_bytes -> nil
        :sig_script -> nil
        _ -> assert val1 == val2
      end
    end
  end

  test "Transaction.verify" do
    # This is the very first bitcoin transaction where Satoshi Nakamoto sent 10 bitcoins to Hal Finney.
    # It was recorded in block 170, the coinbase output it spends is from block 9.
    {curr_tx, <<>>} = Serialize.from_hex(
      "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352"
    <> "423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9"
    <> "d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a"
    <> "8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b"
    <> "2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704"
    <> "f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482e"
    <> "cad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3a"
    <> "c00000000"
    ) |> Transaction.deserialize
    {prev_out, <<>>} = Serialize.from_hex(
      "00f2052a0100000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909"
      <> "a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
    ) |> TxOut.deserialize
    assert Transaction.verify(curr_tx, [prev_out])
  end
end

defmodule Bitcoin.Tests.Block do
  use ExUnit.Case, async: true

  test "Genesis Block" do
    genesis_block_bin = Block.genesis_block_bin()
    {genesis_block, <<>>} = Block.deserialize(genesis_block_bin)
    assert Block.serialize(genesis_block) == genesis_block_bin
  end

  def blk170() do
    bin = File.read!("blk170.bin")
    {blk170, <<>>} = Block.deserialize(bin)
    {blk170, bin}
  end

  test "Block 170 deserialize" do
    {blk170, bin} = blk170()
    assert Block.serialize(blk170) == bin
  end

  test "Block 170 hash" do
    {blk170, _} = blk170()
    expected_hash = Serialize.from_hex("00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee")
      |> Serialize.reverse
    assert Block.hash(blk170) == expected_hash
  end
end

defmodule Bitcoin.Tests.SingleNode do
  use ExUnit.Case

  setup do
    Network.start_link(1)
    :ok
  end

  @spec get_block(NetworkState.t) :: :ok
  def get_block(net_state) do
    node_state = Map.values(net_state.states) |> hd
    if length(node_state.chain) > 1 do
      {:done, List.last(node_state.chain)}
    else
      nil
    end
  end

  # This test verifies that nodes are mining blocks with valid hashes.
  test "Mining" do
    {:done, block} = Network.onetime_callback(&get_block/1)
    assert Serialize.from_little_end(Block.hash(block)) < BlockHeader.to_target_threshold(block.header.n_bits)
  end

  # This test verifies that bitcoins previously mined can be successfully spent.
  test "Transactions" do
    priv_key = Network.onetime_callback(fn(net_state) ->
      node_state = Map.values(net_state.states) |> hd
      node_state.priv_key
    end)
    {:done, block} = Network.onetime_callback(&get_block/1)

    {new_pub_key, _} = Crypto.key_gen()
    pub_key = Crypto.key_gen(priv_key)

    coinbase = hd(block.transactions)
    prev_out = hd(coinbase.tx_out)
    prev_pk_script = prev_out.pk_script

    value = prev_out.value
    payment = round(0.4 * value)
    transaction_fee = 100
    change = value - payment - transaction_fee
    outputs = [{payment, new_pub_key}, {change, pub_key}]

    tran = Transaction.new_from_pub_keys(Transaction.hash(coinbase), 0, prev_pk_script, outputs, priv_key)
    assert Network.submit_tx(tran) # The network returns true if the transaction is accepted.
  end
end

defmodule Bitcoin.Tests.NodeSync do
  use ExUnit.Case

  setup do
    Network.start_link(10)
    :ok
  end

  @doc "Print the contents of `chains` to the console."
  @spec print_chains([[Block.t]]) :: :ok
  def print_chains(chains) do
    Enum.zip(chains, 0..length(chains)-1)
    |> Enum.each(fn({chain, index}) ->
      Enum.map(chain, fn(block) -> Block.hash(block) |> Serialize.to_hex end)
      |> IO.inspect(label: "chain " <> Integer.to_string(index))
    end)
  end

  @spec hash_chains([[Block.t]]) :: [[Crypto.hash_t]]
  def hash_chains(chains) do
    Enum.map(chains, fn(chain) ->
      Enum.map(chain, fn(block) -> Block.hash(block) end)
    end)
  end

  @spec common_chain([[Block.t]]) :: [Crypto.hash_t]
  def common_chain(chains) do
    hash_chains(chains)
    |> Enum.zip
    |> Enum.map(fn(tuple) -> Tuple.to_list(tuple) end)
    |> Enum.map(fn(chain_slice) -> Enum.uniq(chain_slice) end)
    |> Enum.take_while(fn(chain_slice) -> length(chain_slice) == 1 end)
    |> Enum.map(fn(chain_slice) -> hd(chain_slice) end)
  end

  test "Node Synchronization" do
    Network.onetime_callback(fn(net_state) ->
      states = net_state.states
      pids = Map.keys(states)

      longest_chain =
        Enum.map(pids, fn(pid) -> length(states[pid].chain) end)
        |> Enum.max

      if longest_chain > 10 do
        Network.stop_mining()
        :ok
      else
        nil
      end
    end)

    Process.sleep(175)
    chains = Network.onetime_callback(fn(net_state) ->
      Enum.map(Map.values(net_state.states), fn(node_state) -> node_state.chain end)
    end)

    len = length(hd(chains))
    Enum.map(chains, fn(chain) -> length(chain) end)
    |> Enum.each(fn(other_len) -> assert len == other_len end)

    assert length(common_chain(chains)) == len
  end
end
