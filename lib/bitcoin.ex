alias Bitcoin.Dummy
alias Bitcoin.Serialize
alias Bitcoin.TxOut
alias Bitcoin.OutPoint
alias Bitcoin.TxInput
alias Bitcoin.TxIn
alias Bitcoin.CoinBaseIn
alias Bitcoin.Transaction
alias Bitcoin.BlockHeader
alias Bitcoin.Block
alias Bitcoin.Crypto
alias Bitcoin.ScriptContext
alias Bitcoin.Script
alias Bitcoin.Mining
alias Bitcoin.BtcNodeState
alias Bitcoin.BtcNode
alias Bitcoin.NetworkState
alias Bitcoin.Network

defmodule Bitcoin.Dummy do
  @moduledoc """
  This module exists so I can call `Dummy.invert_string` at compile time
  from `Serialize` in order to define a module attribute.
  """

  @doc "Create a map which sends the (unique) characters in `str` to their indices."
  @spec invert_string(String.t) :: %{String.t => non_neg_integer}
  def invert_string(str) do
    Enum.reduce(0..String.length(str)-1, %{}, fn(index, map) ->
      Map.put(map, String.at(str, index), index)
    end)
  end
end

defmodule Bitcoin.Serialize do
  use Bitwise

  @type byte_list :: [non_neg_integer]

  @spec to_byte_list(binary) :: byte_list
  def to_byte_list(bin) do
    for << byte::integer-unsigned-size(8) <- bin>>, do: byte
  end

  @spec from_byte_list(byte_list) :: binary
  def from_byte_list(b_list) do
    Enum.reduce(b_list, <<>>, fn(int, bin) -> bin <> <<int::integer-unsigned-size(8)>> end)
  end

  @spec reverse(binary) :: binary
  def reverse(bin) do
    to_byte_list(bin) |> Enum.reverse |> from_byte_list
  end

  @spec insuf_bytes(integer, non_neg_integer) :: String.t
  def insuf_bytes(int, num_bytes) do
    "Cannot represent "
        <> Integer.to_string(int)
        <> " with "
        <> Integer.to_string(num_bytes)
        <> " bytes."
  end

  @spec to_little_end(integer, non_neg_integer) :: binary
  def to_little_end(int, num_bytes) do
    num_bits = 8 * num_bytes
    two_power = 1 <<< (num_bits - 1)
    if -1 * two_power <= int and int < two_power do
      <<int::signed-little-size(num_bits)>>
    else
      throw(insuf_bytes(int, num_bytes))
    end
  end

  @spec to_little_end_list(integer, non_neg_integer) :: byte_list
  def to_little_end_list(int, num_bytes), do: to_byte_list(to_little_end(int, num_bytes))

  @spec to_little_end_unsigned(non_neg_integer, non_neg_integer) :: binary
  def to_little_end_unsigned(int, num_bytes) do
    num_bits = 8 * num_bytes
    two_power = 1 <<< num_bits
    if 0 <= int and int < two_power do
      <<int::unsigned-little-size(num_bits)>>
    else
      throw(insuf_bytes(int, num_bytes))
    end
  end

  @spec from_little_end(binary) :: integer
  def from_little_end(bin) when is_binary(bin) do
    num_bits = bit_size(bin)
    hd(for << value::signed-little-size(num_bits) <- bin >>, do: value)
  end

  @spec from_little_end(byte_list) :: integer
  def from_little_end(b_list) when is_list(b_list), do: from_little_end(from_byte_list(b_list))

  @spec from_little_end_unsigned(binary) :: integer
  def from_little_end_unsigned(bin) when is_binary(bin) do
    num_bits = bit_size(bin)
    hd(for << value::unsigned-little-size(num_bits) <- bin >>, do: value)
  end

  @spec to_big_end(integer, non_neg_integer) :: binary
  def to_big_end(int, num_bytes) do
    num_bits = 8 * num_bytes
    two_power = 1 <<< (num_bits - 1)
    if -1 * two_power <= int and int < two_power do
      <<int::signed-big-size(num_bits)>>
    else
      throw(insuf_bytes(int, num_bytes))
    end
  end

  @spec to_big_end_list(integer, non_neg_integer) :: byte_list
  def to_big_end_list(int, num_bytes), do: to_byte_list(to_big_end(int, num_bytes))

  @spec to_big_end_unsigned(non_neg_integer, non_neg_integer) :: binary
  def to_big_end_unsigned(int, num_bytes) do
    num_bits = 8 * num_bytes
    two_power = 1 <<< num_bits
    if 0 <= int and int < two_power do
      <<int::unsigned-big-size(num_bits)>>
    else
      throw(insuf_bytes(int, num_bytes))
    end
  end

  @spec from_big_end(binary) :: integer
  def from_big_end(bin) when is_binary(bin) do
    num_bits = bit_size(bin)
    hd(for << value::signed-big-size(num_bits) <- bin >>, do: value)
  end

  @spec from_big_end(byte_list) :: integer
  def from_big_end(b_list) when is_list(b_list), do: from_big_end(from_byte_list(b_list))

  @base58_code "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @spec base58enc(integer, String.t) :: String.t
  defp base58enc(int, str) do
    if 0 == int do
      str
    else
      base58enc(div(int, 58), String.at(@base58_code, rem(int, 58)) <> str)
    end
  end

  @spec base58enc(binary) :: String.t
  def base58enc(data) do
    str = base58enc(from_big_end(data), "")
    pad_char = String.at(@base58_code, 0)
    zeros = for << byte::8 <- data >>, 0 == byte, do: byte
    Enum.reduce(zeros, str, fn(_, str) -> pad_char <> str end)
  end

  @base58_code_inv Dummy.invert_string(@base58_code)

  @spec base58dec(String.t, non_neg_integer) :: binary
  def base58dec(str, num_bytes) do
    Enum.map(0..String.length(str)-1, fn(index) ->
      @base58_code_inv[String.at(str, index)]
    end)
      |> Enum.reduce(0, fn(value, accum) ->
        58 * accum + value
      end)
      |> to_big_end(num_bytes)
  end

  @spec invert_map(map) :: map
  def invert_map(map) do
    Enum.reduce(map, %{}, fn({key, val}, accum) -> Map.put(accum, val, key) end)
  end

  @spec to_hex(binary) :: String.t
  def to_hex(data), do: Base.encode16(data, case: :lower)

  @spec from_hex(String.t) :: binary
  def from_hex(str), do: Base.decode16!(str, case: :mixed)

  @spec to_compact_size_uint(non_neg_integer) :: binary
  def to_compact_size_uint(int) do
    cond do
      0 <= int and int <= 252 -> <<int::integer-unsigned-size(8)>>
      252 < int and int <= 0xffff -> <<0xfd::unsigned-size(8), int::integer-unsigned-little-size(16)>>
      0xffff < int and int <= 0xffffffff -> <<0xfe::unsigned-size(8), int::integer-unsigned-little-size(32)>>
      0xffffffff < int and int <= 0xffffffffffffffff -> <<0xff::unsigned-size(8), int::integer-unsigned-little-size(64)>>
    end
  end

  @spec from_compact_size_uint(binary) :: {non_neg_integer, binary}
  def from_compact_size_uint(bin) do
    <<tag::integer-unsigned-size(8), bin::binary>> = bin
    case tag do
      0xfd ->
        <<value::integer-unsigned-little-size(16), bin::binary>> = bin
        {value, bin}
      0xfe ->
        <<value::integer-unsigned-little-size(32), bin::binary>> = bin
        {value, bin}
      0xff ->
        <<value::integer-unsigned-little-size(64), bin::binary>> = bin
        {value, bin}
      _ -> {tag, bin}
    end
  end

  @type binary_pairs_t :: [{atom, binary}]

  @spec concat_vals(binary_pairs_t, ({atom, binary} -> any)) :: binary
  def concat_vals(pairs, inspect) when is_function(inspect) do
    Enum.each(pairs, inspect)
    Enum.reduce(pairs, <<>>, fn({_, val}, accum) -> accum <> val end)
  end

  @spec concat_vals(binary_pairs_t, boolean) :: binary
  def concat_vals(pairs, inspect) when is_boolean(inspect) do
    if inspect do
      concat_vals(pairs, fn({key, val}) -> IO.inspect(val, label: key, limit: :infinity) end)
    else
      concat_vals(pairs)
    end
  end

  @spec concat_vals(binary_pairs_t) :: binary
  def concat_vals(pairs), do: concat_vals(pairs, fn(_) -> nil end)

  @doc "Inspect `val` after mapping it with `Serialize.to_hex` and give it label `key`."
  def inspect_hex({key, val}) do
    IO.inspect(to_hex(val), label: key, limit: :infinity)
  end
end

defmodule Bitcoin.TxOut do
  alias Bitcoin.TxOut, as: TxOut

  defstruct value: nil, pk_script: nil
  @type t :: %TxOut{
    value: non_neg_integer,
    pk_script: Script.t
  }

  @spec pk_script(<<_::160>>) :: Script.t
  def pk_script(pk_hash) do
    [
      Script.op_dup(),
      Script.op_hash160(),
      Script.op_pushdata(pk_hash),
      Script.op_equalverify(),
      Script.op_checksig()
    ]
  end

  @spec pk_script_key(Crypto.pub_key_t) :: Script.t
  def pk_script_key(pub_key), do: pk_script(Crypto.hash160(pub_key))

  @spec pk_script_addr(String.t) :: Script.t
  def pk_script_addr(address) do
    {:ok, _, pk_hash} = Crypto.payload(address)
    pk_script(pk_hash)
  end

  @spec new(non_neg_integer, String.t) :: TxOut.t
  def new(amount, address), do: %TxOut{value: amount, pk_script: pk_script_addr(address)}

  @spec new_from_key(non_neg_integer, Crypto.pub_key_t) :: TxOut.t
  def new_from_key(amount, pub_key), do: %TxOut{value: amount, pk_script: pk_script_key(pub_key)}

  @spec to_pairs(TxOut.t) :: Serialize.binary_pairs_t
  def to_pairs(tx_out) do
    script_bin = Script.compile(tx_out.pk_script)
    [
      {:value, Serialize.to_little_end(tx_out.value, 8)},
      {:pk_script_bytes, Serialize.to_compact_size_uint(byte_size(script_bin))},
      {:pk_script, script_bin}
    ]
  end

  @spec serialize(TxOut.t, boolean) :: binary
  def serialize(tx_out, inspect \\ false), do: Serialize.concat_vals(to_pairs(tx_out), inspect)

  @spec deserialize(binary) :: {TxOut.t, binary}
  def deserialize(bin) do
    <<value::integer-signed-little-size(64), bin::binary>> = bin
    {script_size, bin} = Serialize.from_compact_size_uint(bin)
    {pk_script, bin} = Script.decompile(bin, byte_size(bin) - script_size)
    {%TxOut{value: value, pk_script: pk_script}, bin}
  end
end

defmodule Bitcoin.OutPoint do
  defstruct hash: nil, index: nil

  @type t :: %OutPoint{
    hash: Crypto.hash_t, # 32 bytes
    index: non_neg_integer
  }

  @type key :: {Crypto.hash_t, non_neg_integer}

  @spec to_key(Crypto.hash_t, non_neg_integer) :: key
  def to_key(hash, index), do: {hash, index}

  @spec to_key(OutPoint.t) :: key
  def to_key(out_point), do: to_key(out_point.hash, out_point.index)

  @type out_point_ser :: <<_::288>>

  @spec out_point_ser_size() :: 36
  def out_point_ser_size(), do: 36

  @spec to_pairs(OutPoint.t) :: Serialize.binary_pairs_t
  def to_pairs(out_point) do
    [
      {:hash, out_point.hash},
      {:index, Serialize.to_little_end_unsigned(out_point.index, 4)}
    ]
  end

  @spec serialize(OutPoint.t, boolean) :: out_point_ser
  def serialize(out_point, inspect \\ false), do: Serialize.concat_vals(to_pairs(out_point), inspect)

  @spec deserialize(out_point_ser) :: {Output.t, binary}
  def deserialize(bin) do
    <<hash::binary-size(32), index::integer-unsigned-little-size(32), bin::binary>> = bin
    {%OutPoint{hash: hash, index: index}, bin}
  end
end

defmodule Bitcoin.TxInput do
  @callback to_pairs(map) :: Serialize.binary_pairs_t
  @callback deserialize(bin :: binary) :: {map, binary}
end

defmodule Bitcoin.TxIn do
  defstruct prev_out: nil, sig_script: [], sequence: 0xffffffff
  @type t :: %TxIn{
    prev_out: OutPoint.t,
    sig_script: Script.t,
    sequence: non_neg_integer
  }

  @behaviour TxInput

  @spec sig_script(binary, Crypto.pub_key_t) :: Script.t
  def sig_script(sig, pub_key) do
    [
      {:OP_PUSHDATA, sig},
      {:OP_PUSHDATA, pub_key}
    ]
  end

  @spec new(OutPoint.t, binary, Crypto.pub_key_t) :: TxIn.t
  def new(prev_out, sig, pub_key), do: %TxIn{prev_out: prev_out, sig_script: sig_script(sig, pub_key)}

  @spec new_unsigned(Crypto.hash_t, non_neg_integer) :: TxIn.t
  def new_unsigned(hash, index), do: %TxIn{prev_out: %OutPoint{hash: hash, index: index}}

  @spec to_pairs(TxIn.t) :: Serialize.binary_pairs_t
  def to_pairs(tx_in) do
    script_bin = Script.compile(tx_in.sig_script)
    [
      {:prev_out, OutPoint.serialize(tx_in.prev_out)},
      {:sig_script_bytes, Serialize.to_compact_size_uint(byte_size(script_bin))},
      {:sig_script, script_bin},
      {:sequence, Serialize.to_little_end_unsigned(tx_in.sequence, 4)}
    ]
  end

  @spec serialize(TxIn.t, boolean) :: binary
  def serialize(tx_in, inspect \\ false), do: Serialize.concat_vals(to_pairs(tx_in), inspect)

  @spec deserialize(binary) :: {TxIn.t, binary}
  def deserialize(bin) do
    {out_point, bin} = OutPoint.deserialize(bin)
    {script_size, bin} = Serialize.from_compact_size_uint(bin)
    {sig_script, bin} = Script.decompile(bin, byte_size(bin) - script_size)
    <<sequence::integer-unsigned-little-size(32), bin::binary>> = bin
    {%TxIn{prev_out: out_point, sig_script: sig_script, sequence: sequence}, bin}
  end
end

defmodule Bitcoin.CoinBaseIn do
  defstruct hash: <<0::256>>, index: 0xffffffff, height: nil, coinbase_script: nil, sequence: 0
  @type t :: %CoinBaseIn{
    hash: Crypto.hash_t,
    index: non_neg_integer,
    height: Script.t,
    coinbase_script: Script.t,
    sequence: non_neg_integer
  }

  @behaviour TxInput

  @spec new(non_neg_integer) :: CoinBaseIn.t
  def new(height) do
    %CoinBaseIn{
      height: [Serialize.to_little_end_unsigned(height, 3) |> Script.op_pushdata],
      coinbase_script: coinbase_script()
    }
  end

  @spec coinbase_script(non_neg_integer) :: Script.t
  def coinbase_script(value) do
    [Script.op_pushdata(Serialize.to_little_end_unsigned(value, 32))]
  end

  @spec coinbase_script() :: Script.t
  def coinbase_script(), do: coinbase_script(0)

  @spec increment_coinbase_script(Script.t) :: Script.t
  def increment_coinbase_script(coinbase_script) when is_list(coinbase_script) do
    value = hd(coinbase_script) |> Serialize.from_little_end_unsigned
    coinbase_script(value + 1)
  end

  @spec increment_coinbase_script(CoinBaseIn.t) :: CoinBaseIn.t
  def increment_coinbase_script(coinbase_in) when is_map(coinbase_in) do
    Map.update!(coinbase_in, :coinbase_script, fn(coinbase_script) ->
      increment_coinbase_script(coinbase_script)
    end)
  end

  @spec to_pairs(CoinBaseIn.t) :: Serialize.binary_pairs_t
  def to_pairs(coinbase) do
    script_bin = Script.compile(coinbase.height ++ coinbase.coinbase_script)
    [
      {:hash, coinbase.hash},
      {:index, Serialize.to_little_end_unsigned(coinbase.index, 4)},
      {:script_size, Serialize.to_compact_size_uint(byte_size(script_bin))},
      {:script, script_bin},
      {:sequence, Serialize.to_little_end_unsigned(coinbase.sequence, 4)}
    ]
  end

  @spec serialize(CoinBaseIn.t, boolean) :: binary
  def serialize(coinbase, inspect \\ false), do: to_pairs(coinbase) |> Serialize.concat_vals(inspect)

  @spec deserialize(binary) :: {CoinBaseIn.t, binary}
  def deserialize(bin) do
    <<
      hash::binary-size(32),
      index::integer-little-unsigned-size(32),
      bin::binary
    >> = bin
    {script_size, bin} = Serialize.from_compact_size_uint(bin)
    {script, bin} = Script.decompile(bin, byte_size(bin) - script_size)
    [height | coinbase_script] = script
    height = [height]
    <<sequence::integer-little-unsigned-size(32), bin::binary>> = bin
    {%CoinBaseIn{
      hash: hash, index: index, height: height, coinbase_script: coinbase_script, sequence: sequence
    }, bin}
  end
end

defmodule Bitcoin.Transaction do
  defstruct version: 1, tx_in: [], tx_out: [], lock_time: 0, coinbase?: false
  @type t :: %Transaction{
    version: non_neg_integer,
    tx_in: [TxIn.t],
    tx_out: [TxOut.t],
    lock_time: non_neg_integer,
    coinbase?: boolean
  }

  @spec new([{Crypto.hash_t, non_neg_integer, Script.t}], [{non_neg_integer, Crypto.addr_data_t}], Crypto.priv_key_t) :: Transaction.t
  def new(inputs, outputs, priv_key) do
    tx_in = Enum.map(inputs, fn({hash, index, _}) ->
      TxIn.new_unsigned(hash, index)
    end)
    tx_out = Enum.map(outputs, fn({amount, address}) ->
      TxOut.new(amount, address)
    end)
    tran = %Transaction{tx_in: tx_in, tx_out: tx_out}
    Enum.reduce(0..length(tx_in) - 1, tran, fn(in_index, tran) ->
      {_, _, prev_pk_script} = Enum.at(inputs, in_index)
      Transaction.sign(tran, prev_pk_script, in_index, priv_key)
    end)
  end

  @spec new(Crypto.hash_t, non_neg_integer, Script.t, [{non_neg_integer, Crypto.addr_data_t}], Crypto.priv_key_t) :: Transaction.t
  def new(hash, index, script, outputs, priv_key), do: new([{hash, index, script}], outputs, priv_key)

  @spec new_from_pub_keys([{Crypto.hash_t, non_neg_integer, Script.t}], [{non_neg_integer, Crypto.pub_key_t}], Crypto.priv_key_t) :: Transaction.t
  def new_from_pub_keys(inputs, outputs, priv_key) do
    outputs = Enum.map(outputs, fn({amount, pub_key}) ->
      {amount, Crypto.address(pub_key)}
    end)
    new(inputs, outputs, priv_key)
  end

  @spec new_from_pub_keys(Crypto.hash_t, non_neg_integer, Script.t, [{non_neg_integer, Crypto.pub_key_t}], Crypto.priv_key_t) :: Transaction.t
  def new_from_pub_keys(hash, index, script, outputs, priv_key), do: new_from_pub_keys([{hash, index, script}], outputs, priv_key)

  @spec to_pairs(Transaction.t) :: Serialize.binary_pairs_t
  def to_pairs(trans) do
    tx_input =
      if trans.coinbase? do
        CoinBaseIn
      else
        TxIn
      end
    [
      {:version, Serialize.to_little_end_unsigned(trans.version, 4)},
      {:tx_in_count, Serialize.to_compact_size_uint(length(trans.tx_in))}
    ]
      ++ Enum.reduce(trans.tx_in, [], fn(tx_in, accum) -> accum ++ tx_input.to_pairs(tx_in) end)
      ++ [{:tx_out_count, Serialize.to_compact_size_uint(length(trans.tx_out))}]
      ++ Enum.reduce(trans.tx_out, [], fn(tx_out, accum) -> accum ++ TxOut.to_pairs(tx_out) end)
      ++ [{:lock_time, Serialize.to_little_end_unsigned(trans.lock_time, 4)}]
  end

  @spec serialize(Transaction.t, boolean | fun) :: binary
  def serialize(trans, inspect \\ false), do: Serialize.concat_vals(to_pairs(trans), inspect)

  @spec deserialize(binary, TxInput.t) :: {Transaction.t, binary}
  defp deserialize(bin, tx_input) do
    <<version::integer-unsigned-little-size(32), bin::binary>> = bin
    {tx_in_size, bin} = Serialize.from_compact_size_uint(bin)
    {tx_in, bin} = Enum.map_reduce(1..tx_in_size, bin, fn(_, bin) -> tx_input.deserialize(bin) end)
    {tx_out_size, bin} = Serialize.from_compact_size_uint(bin)
    {tx_out, bin} = Enum.map_reduce(1..tx_out_size, bin, fn(_, bin) -> TxOut.deserialize(bin) end)
    <<lock_time::integer-unsigned-little-size(32), bin::binary>> = bin
    {%Transaction{version: version, tx_in: tx_in, tx_out: tx_out, lock_time: lock_time}, bin}
  end

  @spec deserialize(binary) :: {Transaction.t, binary}
  def deserialize(bin), do: deserialize(bin, TxIn)

  @spec deserialize_coinbase(binary) :: {Transaction.t, binary}
  def deserialize_coinbase(bin) do
    {trans, bin} = deserialize(bin, CoinBaseIn)
    {Map.put(trans, :coinbase?, true), bin}
  end

  # The hash type for signatures we use is SIGHASH_ALL (hash everything).
  @hash_type 1

  @spec signing_input_bytes(Transaction.t, Script.t, non_neg_integer, boolean) :: binary
  def signing_input_bytes(trans, prev_pk_script, in_index, inspect \\ false) do
    # Set the sig_script of every input to nil.
    trans = Map.put(trans, :tx_in, Enum.map(trans.tx_in, fn(input) -> Map.put(input, :sig_script, nil) end))
    # Set the sig_script of the given input to the given prev_pk_script.
    trans = Map.put(trans, :tx_in, List.update_at(trans.tx_in, in_index, fn(tx) ->
      Map.put(tx, :sig_script, prev_pk_script)
    end))
    # We serialize the transaction and append 1 for the signature type SIGHASH_ALL (hash everything).
    serialize(trans, inspect) <> <<@hash_type::little-unsigned-size(32)>>
  end

  @spec signing_input(Transaction.t, Script.t, non_neg_integer) :: Crypto.hash_t
  def signing_input(trans, prev_pk_script, in_index) do
    Crypto.double_hash(signing_input_bytes(trans, prev_pk_script, in_index))
  end

  @spec signature(Transaction.t, Script.t, non_neg_integer, Crypto.priv_key_t) :: binary
  def signature(trans, prev_pk_script, in_index, priv_key) do
    Crypto.sign_digest(signing_input(trans, prev_pk_script, in_index), priv_key)
      <> <<@hash_type::unsigned-size(8)>>
  end

  @spec sign(Transaction.t, Script.t, non_neg_integer, Crypto.priv_key_t) :: Transaction.t
  def sign(trans, prev_pk_script, in_index, priv_key) do
    sig = signature(trans, prev_pk_script, in_index, priv_key)
    Map.put(trans, :tx_in, List.update_at(trans.tx_in, in_index, fn(input) ->
      Map.put(input, :sig_script, TxIn.sig_script(sig, Crypto.key_gen(priv_key)))
    end))
  end

  @spec verify_signature(Transaction.t, Script.t, non_neg_integer, Crypto.pub_key_t, binary) :: boolean
  def verify_signature(trans, prev_pk_script, in_index, pub_key, sig) do
    size = byte_size(sig) - 1
    hash_type = binary_part(sig, size, 1) |> Serialize.from_little_end_unsigned
    sig = binary_part(sig, 0, size)
    case hash_type do
      @hash_type -> Crypto.verify_digest(signing_input(trans, prev_pk_script, in_index), pub_key, sig)
      _ -> throw("Unkown hash_type encountered: " <> Integer.to_string(hash_type))
    end
  end

  @doc "Verify that the sum of the inputs of a transaction exceed the sum of its outputs."
  @spec verify_value(Transaction.t, [TxOut.t]) :: boolean
  def verify_value(curr_trans, prev_outs) do
    out_value = Enum.reduce(curr_trans.tx_out, 0, fn(output, out_value) ->
      out_value + output.value
    end)
    in_value = Enum.reduce(prev_outs, 0, fn(prev_out, in_value) ->
      in_value + prev_out.value
    end)
    in_value >= out_value
  end

  @doc "Verify that a transaction's input's signature is valid."
  @spec verify(Transaction.t, non_neg_integer, TxOut.t) :: boolean
  def verify(curr_trans, in_index, prev_out) do
    curr_in = Enum.at(curr_trans.tx_in, in_index)
    sig_script = curr_in.sig_script
    prev_pk_script = prev_out.pk_script
    Script.exec(sig_script ++ prev_pk_script, curr_trans, prev_pk_script, in_index)
  end

  @doc "Verify that a transaction is valid."
  @spec verify(Transaction.t, [TxOut.t]) :: boolean
  def verify(curr_tran, prev_outs) do
    if Enum.any?(prev_outs, fn(prev_out) -> is_nil(prev_out) end) do
      false
    else
      verify_value(curr_tran, prev_outs)
        and Enum.map(0..length(curr_tran.tx_in) - 1, fn(in_index) ->
          verify(curr_tran, in_index, Enum.at(prev_outs, in_index))
        end)
          |> Enum.all?(fn(input_valid?) -> true == input_valid? end)
    end
  end

  @spec hash(Transaction.t) :: Crypto.hash_t
  def hash(trans), do: serialize(trans) |> Crypto.double_hash
end

defmodule Bitcoin.BlockHeader do
  @moduledoc "Code for working with `%BlockHeader` structs."
  #@n_bits 0x1d00ffff # difficulty 1
  @n_bits 0x1f00ffff

  defstruct version: 1, hash_prev_block: nil, hash_merkle_root: nil, time: 0, n_bits: @n_bits, nonce: 0

  @typedoc "A header for each block in the block chain."
  @type t :: %BlockHeader{
    version: integer,
    hash_prev_block: Crypto.hash_t, # 32 bytes
    hash_merkle_root: Crypto.hash_t, # 32 bytes
    time: non_neg_integer,
    n_bits: non_neg_integer, # difficulty 1 -> 0x1d00ffff
    nonce: non_neg_integer
  }

  @spec n_bits() :: non_neg_integer
  def n_bits(), do: @n_bits

  @spec new(Crypto.hash_t, Crypto.hash_t, non_neg_integer) :: BlockHeader.t
  def new(hash_prev_block, hash_merkle_root, n_bits) do
    %BlockHeader{
      hash_prev_block: hash_prev_block, hash_merkle_root: hash_merkle_root,
      time: :os.system_time(:seconds), n_bits: n_bits
    }
  end

  @spec new(Crypto.hash_t, Crypto.hash_t) :: BlockHeader.t
  def new(hash_prev_block, hash_merkle_root), do: new(hash_prev_block, hash_merkle_root, @n_bits)

  @spec to_target_threshold(non_neg_integer) :: integer
  def to_target_threshold(n_bits) do
    bin = Serialize.to_big_end(n_bits, 4)
    <<exponent::unsigned-size(8), mantissa::signed-big-size(24)>> = bin
    power = :math.pow(256, exponent - 3)
    round(mantissa * power)
  end

  @spec target_threshold(BlockHeader.t) :: non_neg_integer
  def target_threshold(header), do: to_target_threshold(header.n_bits)

  @spec to_pairs(BlockHeader.t) :: Serialize.binary_pair_t
  def to_pairs(header) do
    [
      {:version, Serialize.to_little_end(header.version, 4)},
      {:hash_prev_block, header.hash_prev_block},
      {:hash_merkle_root, header.hash_merkle_root},
      {:time, Serialize.to_little_end_unsigned(header.time, 4)},
      {:n_bits, Serialize.to_little_end_unsigned(header.n_bits, 4)},
      {:nonce, Serialize.to_little_end_unsigned(header.nonce, 4)}
    ]
  end

  @spec serialize(BlockHeader.t, boolean) :: binary
  def serialize(header, inspect \\ false), do: Serialize.concat_vals(to_pairs(header), inspect)

  @spec deserialize(binary) :: {BlockHeader.t, binary}
  def deserialize(bin) do
    <<
      version::integer-signed-little-size(32),
      hash_prev_block::binary-size(32),
      hash_merkle_root::binary-size(32),
      time::integer-unsigned-little-size(32),
      n_bits::integer-unsigned-little-size(32),
      nonce::integer-unsigned-little-size(32),
      bin::binary
    >> = bin
    {%BlockHeader{
      version: version, hash_prev_block: hash_prev_block, hash_merkle_root: hash_merkle_root,
      time: time, n_bits: n_bits, nonce: nonce
    }, bin}
  end

  @doc "Hash the serialized header using Crypto.double_hash."
  @spec hash(Header.t) :: Crypto.hash_t
  def hash(header), do: serialize(header) |> Crypto.double_hash
end

defmodule Bitcoin.Block do
  defstruct header: %BlockHeader{}, transactions: []
  @type t :: %Block{
    header: BlockHeader.t,
    transactions: [Transaction.t]
  }

  @genesis_block_bin Serialize.from_hex(
    "01000000000000000000000000000000"
    <> "00000000000000000000000000000000"
    <> "000000003BA3EDFD7A7B12B27AC72C3E"
    <> "67768F617FC81BC3888A51323A9FB8AA"
    <> "4B1E5E4A29AB5F49FFFF001D1DAC2B7C"
    <> "01010000000100000000000000000000"
    <> "00000000000000000000000000000000"
    <> "000000000000FFFFFFFF4D04FFFF001D"
    <> "0104455468652054696D65732030332F"
    <> "4A616E2F32303039204368616E63656C"
    <> "6C6F72206F6E206272696E6B206F6620"
    <> "7365636F6E64206261696C6F75742066"
    <> "6F722062616E6B73FFFFFFFF0100F205"
    <> "2A01000000434104678AFDB0FE554827"
    <> "1967F1A67130B7105CD6A828E03909A6"
    <> "7962E0EA1F61DEB649F6BC3F4CEF38C4"
    <> "F35504E51EC112DE5C384DF7BA0B8D57"
    <> "8A4C702B6BF11D5FAC00000000"
  )

  @doc "Returns the serialized genesis block."
  @spec genesis_block_bin() :: binary
  def genesis_block_bin(), do: @genesis_block_bin

  @btc2satoshi 100000000

  @spec btc2satoshi(number) :: number
  def btc2satoshi(btc), do: btc * @btc2satoshi

  @spec reward(non_neg_integer) :: non_neg_integer
  def reward(_), do: 50 # to be rewritten as a function of height

  @spec new(non_neg_integer, Crypto.pub_key_t, Crypto.hash_t, non_neg_integer) :: Block.t
  def new(height, pub_key, hash_prev_block, n_bits) do
    tx_in = CoinBaseIn.new(height)
    tx_out = TxOut.new_from_key(btc2satoshi(reward(height)), pub_key)
    coinbase = %Transaction{tx_in: [tx_in], tx_out: [tx_out], coinbase?: true}
    transactions = [coinbase]
    hash_merkle_root = merkle_root(transactions)
    header = BlockHeader.new(hash_prev_block, hash_merkle_root, n_bits)
    %Block{header: header, transactions: transactions}
  end

  @spec new(non_neg_integer, Crypto.pub_key_t, Crypto.hash_t) :: Block.t
  def new(height, pub_key, hash_prev_block), do: new(height, pub_key, hash_prev_block, BlockHeader.n_bits())

  @spec to_pairs(Block.t) :: Serialize.binary_pair_t
  def to_pairs(block) do
    BlockHeader.to_pairs(block.header)
    ++ [{:tx_count, Serialize.to_compact_size_uint(length(block.transactions))}]
    ++ Enum.reduce(block.transactions, [], fn(transaction, accum) ->
      accum ++ Transaction.to_pairs(transaction)
    end)
  end

  @spec serialize(Block.t, boolean | function) :: binary
  def serialize(block, inspect \\ false), do: Serialize.concat_vals(to_pairs(block), inspect)

  @spec deserialize(binary) :: {Block.t, binary}
  def deserialize(bin) do
    {header, bin} = BlockHeader.deserialize(bin)
    {num_tx, bin} = Serialize.from_compact_size_uint(bin)
    {coinbase, bin} = Transaction.deserialize_coinbase(bin)
    {transactions, bin} =
      if num_tx >= 2 do
        Enum.map_reduce(2..num_tx, bin, fn(_, bin) ->
          Transaction.deserialize(bin)
        end)
      else
        {[], bin}
      end
    transactions = [coinbase] ++ transactions
    {%Block{header: header, transactions: transactions}, bin}
  end

  @doc "Returns the genesis block."
  @spec genesis_block() :: Block.t
  def genesis_block() do
    {genesis_block, <<>>} = deserialize(@genesis_block_bin)
    genesis_block
  end

  @spec merkle_root(list) :: Crypto.hash_t
  def merkle_root(transactions) do
    Enum.map(transactions, fn(trans) -> Transaction.hash(trans) end) |> Crypto.merkle_root
  end

  @spec hash(Block.t) :: Crypto.hash_t
  def hash(block), do: BlockHeader.hash(block.header)

  @spec hash_value(Block.t) :: non_neg_integer
  def hash_value(block), do: hash(block) |> Serialize.from_little_end_unsigned

  @spec valid?(Block.t, Block.t) :: boolean
  def valid?(prev_block, curr_block) do
    target = BlockHeader.to_target_threshold(curr_block.header.n_bits)
    if hash(prev_block) == curr_block.header.hash_prev_block
      and merkle_root(curr_block.transactions) == curr_block.header.hash_merkle_root
      and hash_value(curr_block) < target
    do
      true
    else
      false
    end
  end
end

defmodule Bitcoin.Crypto do
  @curve :secp256k1
  @hash :sha256
  @type hash_t :: <<_::256>>
  @sig_algo :ecdsa
  @testnet_addr_ver 0x6f # The version byte for P2PKH scripts on testnet.
  @mainnet_addr_ver 0x00 # P2PKH on mainnet

  @type pub_key_t :: <<_::520>>
  @type priv_key_t :: <<_::256>>
  @type addr_data_t :: <<_::200>>

  @spec key_gen() :: {pub_key_t, priv_key_t}
  def key_gen(), do: :crypto.generate_key(:ecdh, @curve)

  @spec key_gen(priv_key_t) :: pub_key_t
  def key_gen(priv_key) do
    {pub_key, _} = :crypto.generate_key(:ecdh, @curve, priv_key)
    pub_key
  end

  @doc """
    Signs the given digest with the given private key. Make sure you compute
    the digest using the appropriate hash function before calling `sign`.
  """
  @spec sign_digest(binary, priv_key_t) :: binary
  def sign_digest(digest, priv_key) do
    :crypto.sign(@sig_algo, @hash, {:digest, digest}, [priv_key, @curve])
  end

  @doc "Sign `msg` with `priv_key` after digesting `msg` with `double_hash`."
  @spec sign(binary, priv_key_t) :: binary
  def sign(msg, priv_key), do: sign_digest(double_hash(msg), priv_key)

  @spec verify_digest(binary, pub_key_t, binary) :: boolean
  def verify_digest(digest, pub_key, sig) do
    :crypto.verify(@sig_algo, @hash, {:digest, digest}, sig, [pub_key, @curve])
  end

  @spec verify(binary, pub_key_t, binary) :: boolean
  def verify(msg, pub_key, sig), do: verify_digest(double_hash(msg), pub_key, sig)

  @spec double_hash(binary) :: hash_t
  def double_hash(bin), do: :crypto.hash(@hash, :crypto.hash(@hash, bin))

  @zero_hash <<0::256>>

  @doc "This is the hash which consists of all zeros, not the hash of zero."
  def zero_hash(), do: @zero_hash

  @spec hash160(pub_key_t) :: <<_::160>>
  def hash160(pub_key), do: :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))

  @spec address_data(pub_key_t, <<_::8>>) :: addr_data_t
  def address_data(pub_key, ver_byte) do
    payload = hash160(pub_key)
    ver_payload = ver_byte <> payload
    full_checksum = :crypto.hash(:sha256, :crypto.hash(:sha256, ver_payload))
    << checksum::binary-size(4)-unit(8), _::binary >> = full_checksum
    ver_payload <> checksum
  end

  @spec address_data_testnet(pub_key_t) :: addr_data_t
  def address_data_testnet(pub_key), do: address_data(pub_key, <<@testnet_addr_ver>>)

  @spec address_data_mainnet(pub_key_t) :: addr_data_t
  def address_data_mainnet(pub_key), do: address_data(pub_key, <<@mainnet_addr_ver>>)

  @spec address(pub_key_t) :: String.t
  def address(pub_key), do: Serialize.base58enc(address_data_testnet(pub_key))

  @spec payload(String.t) :: {:ok, <<_::8>>, <<_::160>>} | {:error}
  def payload(address) do
    <<version::binary-size(1), payload::binary-size(20), checksum::binary-size(4)>>
      = Serialize.base58dec(address, 25)
    full_checksum = :crypto.hash(:sha256, :crypto.hash(:sha256, version <> payload))
    case full_checksum do
      <<^checksum::binary-size(4), _::binary>> -> {:ok, version, payload}
      _ -> {:error}
    end
  end

  @spec merkle_root_priv([Crypto.hash_t]) :: Crypto.hash_t
  defp merkle_root_priv(hashes) do
    length = length(hashes)
    if 1 == length do
      hd(hashes)
    else
      hashes =
        if rem(length, 2) == 1 do
          hashes ++ [List.last(hashes)]
        else
          hashes
        end
      Enum.chunk_every(hashes, 2)
        |> Enum.map(fn([l, r]) -> Crypto.double_hash(l <> r) end)
        |> merkle_root
    end
  end

  @doc "Compute the Merkle root of a list of hashes."
  @spec merkle_root([Crypto.hash_t]) :: Crypto.hash_t
  def merkle_root(hashes) do
    Enum.map(hashes, &Serialize.reverse/1) |> merkle_root_priv |> Serialize.reverse
  end
end

defmodule Bitcoin.ScriptContext do
  defstruct curr_trans: nil, prev_pk_script: [], in_index: nil
  @type t :: %ScriptContext{
    curr_trans: Transaction.t,
    prev_pk_script: Script.t,
    in_index: non_neg_integer
  }
end

defmodule Bitcoin.Script do
  @type t :: [atom | {atom, binary}]

  @opcodes %{
    0 => :OP_0, 1 => :OP_1, 76 => :OP_PUSHDATA1, 77 => :OP_PUSHDATA2, 78 => :OP_PUSHDATA4,
    118 => :OP_DUP, 136 => :OP_EQUALVERIFY, 169 => :OP_HASH160, 172 => :OP_CHECKSIG
  }
  @opcodes_inv Serialize.invert_map(@opcodes)

  @type stack_t :: list(binary)

  @spec get_op_byte(atom) :: non_neg_integer
  def get_op_byte(op_code), do: @opcodes_inv[op_code]

  @spec is_valid_pushdata?(non_neg_integer) :: boolean
  def is_valid_pushdata?(op_byte), do: 1 <= op_byte and op_byte <= 75

  @spec get_op_code(non_neg_integer) :: atom
  def get_op_code(op_byte) do
    if is_valid_pushdata?(op_byte) do
      :OP_PUSHDATA
    else
      @opcodes[op_byte]
    end
  end

  @spec op_0() :: :OP_0
  def op_0(), do: :OP_0

  @spec op_1() :: :OP_1
  def op_1(), do: :OP_1

  @spec op_pushdata(binary) :: {:OP_PUSHDATA, binary}
  def op_pushdata(data) do
    size = byte_size(data)
    if is_valid_pushdata?(size) do
      {:OP_PUSHDATA, data}
    else
      throw("Data length invalid (must be between 1 and 75 bytes): "
        <> Integer.to_string(size)
      )
    end
  end

  @spec op_dup() :: :OP_DUP
  def op_dup(), do: :OP_DUP

  @spec op_equalverify() :: :OP_EQUALVERIFY
  def op_equalverify(), do: :OP_EQUALVERIFY

  @spec op_hash160() :: :OP_HASH160
  def op_hash160(), do: :OP_HASH160

  @spec op_checksig() :: :OP_CHECKSIG
  def op_checksig(), do: :OP_CHECKSIG

  @spec compile(Script.t) :: binary
  def compile(op_codes) when is_list(op_codes) do
    Enum.map(op_codes, fn(op_code) ->
      case op_code do
        {:OP_PUSHDATA, data} -> <<byte_size(data)::integer-unsigned-size(8)>> <> data
        _ -> <<get_op_byte(op_code)::integer-unsigned-size(8)>>
      end
    end)
    |> Enum.reduce(<<>>, fn(op_bytes, accum) -> accum <> op_bytes end)
  end

  @spec compile(nil) :: <<>>
  def compile(op_codes) when op_codes == nil, do: <<>>

  @spec decompile(binary) :: {Script.t, binary}
  def decompile(bin), do: decompile(bin, 0, [])

  @spec decompile(binary, non_neg_integer) :: {Script.t, binary}
  def decompile(bin, halt_size), do: decompile(bin, halt_size, [])

  @spec decompile(binary, non_neg_integer, Script.t) :: {Script.t, binary}
  defp decompile(bin, halt_size, script) do
    if byte_size(bin) == halt_size do
      {script, bin}
    else
      <<op_byte::integer-unsigned-size(8), bin::binary>> = bin
      case get_op_code(op_byte) do
        :OP_PUSHDATA ->
          <<data::binary-size(op_byte), bin::binary>> = bin
          decompile(bin, halt_size, script ++ [{:OP_PUSHDATA, data}])
        op_code -> decompile(bin, halt_size, script ++ [op_code])
      end
    end
  end

  @spec exec(Script.t, stack_t, ScriptContext.t) :: boolean
  defp exec(script, stack, context) do
    if Enum.empty?(script) do
      case hd(stack) do
        true -> true
        false -> false
        other -> raise("Unknown value at the top of the stack: " <> inspect(other))
      end
    else
      [op_code | script] = script
      case op_code do
        {:OP_PUSHDATA, data} -> exec(script, [data] ++ stack, context)
        _ -> exec(script, stack, context, op_code)
      end
    end
  end

  @spec exec(Script.t, Transaction.t, Script.t, non_neg_integer) :: boolean
  def exec(script, curr_trans, prev_pk_script, in_index) when is_integer(in_index) do
    exec(script, [], %ScriptContext{curr_trans: curr_trans, prev_pk_script: prev_pk_script, in_index: in_index})
  end

  @spec exec(Script.t, stack_t, ScriptContext.t, :OP_0) :: boolean
  def exec(script, stack, context, :OP_0), do: exec(script, [0] ++ stack, context)

  @spec exec(Script.t, stack_t, ScriptContext.t, :OP_DUP) :: boolean
  def exec(script, [top | stack], context, :OP_DUP), do: exec(script, [top, top] ++ stack, context)

  @spec exec(Script.t, stack_t, ScriptContext.t, :OP_HASH160) :: boolean
  def exec(script, [top | stack], context, :OP_HASH160) do
    exec(script, [Crypto.hash160(top)] ++ stack, context)
  end

  @spec exec(Script.t, stack_t, ScriptContext.t, :OP_EQUALVERIFY) :: boolean
  def exec(script, stack, context, :OP_EQUALVERIFY) do
    [first | [second | stack]] = stack
    if first == second do
      exec(script, stack, context)
    else
      false
    end
  end

  @spec exec(Script.t, stack_t, ScriptContext.t, :OP_CHECKSIG) :: boolean
  def exec(script, stack, context, :OP_CHECKSIG) do
    [pub_key | [sig | stack]] = stack
    stack =
      if Transaction.verify_signature(
        context.curr_trans, context.prev_pk_script, context.in_index, pub_key, sig
      ) do
        [true] ++ stack
      else
        [false] ++ stack
      end
    exec(script, stack, context)
  end
end

defmodule Bitcoin.Mining do
  use Bitwise

  @max_nonce (1 <<< 32) - 1

  @spec increment_block(Block.t) :: Block.t
  def increment_block(block) do
    nonce = block.header.nonce + 1
    if nonce > @max_nonce do
      Map.update!(block, :header, fn(header) ->
        Map.put(header, :nonce, 0)
      end)
      |> Map.update!(:transactions, fn(transactions) ->
        List.update_at(transactions, 0, fn(coinbase) ->
          List.update_at(coinbase.tx_in, 0, fn(coinbase_in) ->
            CoinBaseIn.increment_coinbase_script(coinbase_in)
          end)
        end)
      end)
    else
      Map.update!(block, :header, fn(header) ->
        Map.put(header, :nonce, nonce)
      end)
    end
  end

  @spec mine(Block.t, non_neg_integer) :: :ok
  def mine(block, target) do
    hash_val = Block.hash_value(block)
    if hash_val < target do
      BtcNode.block_mined(block)
    else
      mine(increment_block(block), target)
    end
  end
end

defmodule Bitcoin.BtcNodeState do
  @genesis_block Block.genesis_block()

  @moduledoc "The state of a node in the BTC network."
  defstruct peers: [], chain: [@genesis_block], index: %{}, current_block: nil, pub_key: nil, priv_key: nil,
    target: BlockHeader.to_target_threshold(BlockHeader.n_bits()), miner: nil, transaction_q: []

  @type t :: %BtcNodeState{
    peers: [pid], # The peers this node knows about.
    chain: [Block.t], # The block chain.
    # An index of unspent transaction outputs. The keys are {tx hash, output index}.
    index: %{OutPoint.key => TxOut.t},
    current_block: Block.t | nil, # The block currently being mined.
    pub_key: Crypto.pub_key_t,
    priv_key: Crypto.priv_key_t,
    target: non_neg_integer,
    miner: pid | nil,
    transaction_q: [Transaction.t]
  }

  @spec new() :: BtcNodeState.t
  def new() do
    {pub_key, priv_key} = Crypto.key_gen()
    %BtcNodeState{pub_key: pub_key, priv_key: priv_key}
  end
end

defmodule Bitcoin.BtcNode do
  @moduledoc "A full node in the network. Nodes also mine blocks."
  use GenServer
  use Bitwise

  ## Server utility functions.

  @doc "Create a new block at `state.current_block` to be mined."
  @spec new_block(BtcNodeState.t) :: BtcNodeState.t
  def new_block(state) do
    prev_block_hash =
      if Enum.any?(state.chain) do # Why am I checking this? The genesis block will always root the chain.
        Block.hash(List.last(state.chain))
      else
        Crypto.zero_hash()
      end
    Map.put(state, :current_block,
      Block.new(length(state.chain), state.pub_key, prev_block_hash)
      |> Map.update!(:transactions, fn(transactions) ->
        transactions ++ state.transaction_q
      end)
    )
    |> Map.put(:transaction_q, [])
  end

  @doc "Start a task to mine `state.current_block` and store its pid in `state.miner`."
  @spec start_miner(BtcNodeState.t) :: BtcNodeState.t
  def start_miner(state) do
    {:ok, pid} = Task.start_link(fn -> Mining.mine(state.current_block, state.target) end)
    Process.group_leader(pid, self())
    Map.put(state, :miner, pid)
  end

  @doc "Stop `state.miner`."
  @spec stop_miner(BtcNodeState.t) :: BtcNodeState.t
  def stop_miner(state) do
    miner = state.miner
    if is_pid(miner) do
      Process.exit(miner, :normal)
    end
    Map.put(state, :miner, nil)
  end

  @doc """
  Kill `state.miner`, move the transactions in `state.current_block` back to `state.transaction_q`,
  then set `state.current_block` to `nil`.
  """
  @spec interrupt_miner(BtcNodeState.t) :: BtcNodeState.t
  def interrupt_miner(state) do
    stop_miner(state)
    |> Map.update!(:transaction_q, fn(transaction_q) ->
      # Grab the non-coinbase transactions from the current block.
      if nil != state.current_block do
        [_coinbase | prev_transactions] = state.current_block.transactions
        prev_transactions ++ transaction_q
      else
        transaction_q
      end
    end)
    |> Map.put(:current_block, nil)
  end

  @doc "Send my state to the Network."
  @spec notify_network(BtcNodeState.t) :: BtcNodeState.t
  def notify_network(state) do
    Network.node_state_change(state)
    state
  end

  @doc "Get the previous outputs used as inputs by `curr_tran` from `state.index`."
  @spec prev_outs(BtcNodeState.t, Transaction.t) :: [TxOut.t]
  def prev_outs(state, curr_tran) do
    Enum.map(curr_tran.tx_in, fn(curr_in) ->
      Map.get(state.index, OutPoint.to_key(curr_in.prev_out))
    end)
  end

  @doc "Verify that `curr_tran` is a valid transaction."
  @spec verify(BtcNodeState.t, Transaction.t) :: boolean
  def verify(state, curr_tran) do
    Transaction.verify(curr_tran, prev_outs(state, curr_tran))
  end

  @doc "Check if a given transaction is already queued."
  @spec queued?(BtcNodeState.t, Transaction.t) :: boolean
  def queued?(state, curr_tran) do
    Enum.any?(state.transaction_q, fn(other_tran) -> curr_tran == other_tran end)
  end

  @doc "Add `trans` to `state.transaction_q`."
  @spec enqueue(BtcNodeState.t, Transaction.t) :: BtcNodeState.t
  def enqueue(state, trans) do
    spent_outpoints = Enum.map(trans.tx_in, fn(input) -> OutPoint.to_key(input.prev_out) end)
    Map.update!(state, :transaction_q, fn(transaction_q) ->
      transaction_q ++ [trans]
    end)
    |> Map.update!(:index, fn(index) -> Map.drop(index, spent_outpoints) end)
  end

  @doc "Update `state.index` with the transaction outputs in `block`."
  @spec update_index(BtcNodeState.t, Block.t) :: BtcNodeState.t
  def update_index(state, block) do
    Map.update!(state, :index, fn(index) ->
      Enum.reduce(block.transactions, index, fn(tran, index) ->
        hash = Transaction.hash(tran)
        Enum.reduce(0..length(tran.tx_out) - 1, index, fn(out_index, index) ->
          Map.put(index, OutPoint.to_key(hash, out_index), Enum.at(tran.tx_out, out_index))
        end)
      end)
    end)
  end

  @doc "Remove the transactions in `block` from `state.transaction_q`."
  @spec update_queue(BtcNodeState.t, Block.t) :: BtcNodeState.t
  def update_queue(state, block) do
    # Any transaction with a hash in this list should be removed from the queue
    # (since it is already in a block).
    remove_list = Enum.map(block.transactions, fn(transaction) ->
      Transaction.hash(transaction)
    end)
    Map.update!(state, :transaction_q, fn(transaction_q) ->
      Enum.reject(transaction_q, fn(transaction) ->
        transaction_hash = Transaction.hash(transaction)
        Enum.any?(remove_list, fn(hash) ->
          transaction_hash == hash
        end)
      end)
    end)
  end

  @doc "Add `block` to `state.chain`."
  @spec add_block(BtcNodeState.t, Block.t) :: BtcNodeState.t
  def add_block(state, block) do
    Map.update!(state, :chain, fn(chain) ->
      chain ++ [block]
    end)
    |> update_queue(block)
    |> update_index(block)
    |> interrupt_miner
    |> new_block
    |> start_miner
  end

  @doc "Cast a message to every pid in `state.peers` except `except`."
  @spec cast_all(BtcNodeState.t, pid | nil, term) :: :ok
  def cast_all(state, except, msg) do
    targets = Enum.filter(state.peers, fn(peer) -> peer != except end)
    Enum.each(targets, fn(peer) ->
      GenServer.cast(peer, msg)
    end)
  end

  @doc "Broadcast `block` to `state.peers`."
  @spec broadcast_block(BtcNodeState.t, Block.t) :: BtcNodeState.t
  def broadcast_block(state, block) do
    cast_all(state, nil, {:block, block, self()})
    state
  end

  @doc "Verify `tran` and enqueue it if it is valid and not already enqueued."
  @spec process_tx(BtcNodeState.t, Transaction.t) :: {boolean, BtcNodeState.t}
  def process_tx(state, tran) do
    if verify(state, tran) and not queued?(state, tran) do
      {true, enqueue(state, tran)}
    else
      {false, state}
    end
  end

  @debug true

  @spec log_debug(String.t) :: :ok
  def log_debug(msg) do
    if @debug do
      IO.puts(:stderr, "#{inspect(self())} #{msg}")
    end
  end

  @spec block_valid?(BtcNodeState.t, Block.t) :: boolean
  def block_valid?(state, block), do: Block.valid?(List.last(state.chain), block)

  @doc "Find the index of `block.header.hash_prev_block` in `chain`. Returns `nil` if not found."
  @spec find_parent_index([Block.t], Block.t) :: non_neg_integer
  def find_parent_index(chain, block) do
    prev_hash = block.header.hash_prev_block
    Enum.find_index(chain, fn(other_block) ->
      Block.hash(other_block) == prev_hash
    end)
  end

  @spec pow(number, number) :: integer
  def pow(base, exponent), do: :math.pow(base, exponent) |> round

  @spec make_block_locator([Crypto.hash_t]) :: [Crypto.hash_t]
  def make_block_locator(chain) do
    chain_len = length(chain)
    locator =
      List.foldr(Enum.to_list(1..chain_len-1), [], fn(index, locator) ->
        len = length(locator)
        if len < 10 or pow(2, len - 9) + 10 == chain_len - index do
          locator ++ [Enum.at(chain, index)]
        else
          locator
        end
      end)
    locator ++ [hd(chain)]
  end

  @doc "Find the index of the first matching member of `locator` in `hashes`."
  @spec find_index([Crypto.hash_t], [Crypto.hash_t]) :: non_neg_integer | nil
  def find_index(hashes, locator) do
    if length(locator) == 0 do
      nil
    else
      [hash | locator] = locator
      index = Enum.find_index(hashes, fn(other_hash) -> other_hash == hash end)
      if index == nil do
        find_index(hashes, locator)
      else
        index
      end
    end
  end

  @doc "Determine if `chain` is a valid block chain."
  @spec chain_valid?([Block.t]) :: boolean
  def chain_valid?(chain) do
    Enum.all?(1..length(chain)-1, fn(index) ->
      Block.valid?(Enum.at(chain, index-1), Enum.at(chain, index))
    end)
  end

  ## Server Functions

  @spec init(any) :: {:ok, BtcNodeState.t}
  def init(_), do: {:ok, BtcNodeState.new()}

  @spec handle_call({:get_state}, GenServer.from, BtcNodeState.t) :: {:reply, BtcNodeState.t, BtcNodeState.t}
  def handle_call({:get_state}, _, state), do: {:reply, state, state}

  @spec handle_call({:submit_tx, Transaction.t}, GenServer.from, BtcNodeState.t) :: {:reply, boolean, BtcNodeState.t}
  def handle_call({:submit_tx, tran}, from, state) do
    {reply, state} = process_tx(state, tran)
    if reply do
      cast_all(state, from, {:tx, tran})
    end
    {:reply, reply, state}
  end

  @spec handle_cast({:tx, Transaction.t}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:tx, tran}, state) do
    {_, state} = process_tx(state, tran)
    {:noreply, state}
  end

  @spec handle_cast({:block_mined, Block.t}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:block_mined, block}, state) do
    state =
      if block_valid?(state, block) do
        broadcast_block(state, block)
        add_block(state, block)
      else
        new_block(state) |> start_miner |> update_index(block)
      end
    {:noreply, state |> notify_network}
  end

  @spec handle_cast({:block, Block.t}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:block, block, from}, state) do
    state =
      if Block.hash(List.last(state.chain)) == block.header.hash_prev_block do
        # The block points to the end of my chain.
        if block_valid?(state, block) do
          # The block is valid, add it to my chain.
          add_block(state, block)
        else
          # The block is invalid, this is a bug.
          throw("I can't continue, somebody sent me an invalid block!")
        end
      else
        # We've detected a fork
        if parent_index = find_parent_index(state.chain, block) do
          # Our chain is longer. Send blocks to the node that sent this message.
          GenServer.cast(from, {:send_blocks, Enum.slice(state.chain, parent_index..length(state.chain))})
          state
        else
          # This block is an orphan. The sender's chain could be longer, so request blocks from them.
          GenServer.cast(from, {:get_blocks, make_block_locator(state.chain), self()})
          state
        end
      end
    {:noreply, state |> notify_network}
  end

  @spec handle_cast({:get_blocks, [Crypto.hash_t], pid}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:get_blocks, block_locator, from}, state) do
    hashes = Enum.map(state.chain, &Block.hash/1)
    locator = Enum.map(block_locator, &Block.hash/1)
    match_index = find_index(hashes, locator)
    GenServer.cast(from, {:send_blocks, Enum.slice(state.chain, match_index+1..length(state.chain))})
    {:noreply, state}
  end

  @spec handle_cast({:send_blocks, [Block.t]}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:send_blocks, blocks}, state) do
    parent_index = find_parent_index(state.chain, hd(blocks))
    proposed_chain = Enum.slice(state.chain, 0..parent_index) ++ blocks
    state =
      if length(proposed_chain) > length(state.chain) do
        if chain_valid?(proposed_chain) do
          Map.put(state, :chain, proposed_chain)
        else
          # Throw an exception to signal that a bug was detected.
          throw("I can't live in a world where the longest chain is invalid!")
        end
      else
        state
      end
    {:noreply, state |> notify_network}
  end

  @spec handle_cast({:set_peers, [pid]}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:set_peers, peers}, state), do: {:noreply, Map.put(state, :peers, peers)}

  @spec handle_cast({:start_mining}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:start_mining}, state), do: {:noreply, new_block(state) |> start_miner}

  @spec handle_cast({:stop_mining}, BtcNodeState.t) :: {:noreply, BtcNodeState.t}
  def handle_cast({:stop_mining}, state), do: {:noreply, interrupt_miner(state)}

  @spec handle_cast({:stop}, BtcNodeState.t) :: {:stop, :normal, BtcNodeState.t}
  def handle_cast({:stop}, state) do
    stop_miner(state)
    {:stop, :normal, state}
  end

  ## Client Functions

  @doc "Start a node."
  @spec start() :: pid
  def start() do
    case GenServer.start(__MODULE__, {}) do
      {:ok, pid} -> pid
      {:error, reason} -> raise(Exception.format_exit(reason))
    end
  end

  @spec start_link() :: pid
  def start_link() do
    case GenServer.start_link(__MODULE__, {}) do
      {:ok, pid} -> pid
      {:error, reason} -> raise(Exception.format_exit(reason))
    end
  end

  @spec stop(pid) :: :ok
  def stop(pid) do
    GenServer.cast(pid, {:stop})
  end

  @spec get_state(pid) :: BtcNodeState.t
  def get_state(pid), do: GenServer.call(pid, {:get_state})

  @spec block_mined(Block.t) :: :ok
  def block_mined(block) do
    GenServer.cast(Process.group_leader(), {:block_mined, block})
  end

  @spec set_peers(pid, [pid]) :: :ok
  def set_peers(pid, peers), do: GenServer.cast(pid, {:set_peers, peers})

  @spec submit_tx(pid, Transaction.t) :: boolean
  def submit_tx(pid, tran), do: GenServer.call(pid, {:submit_tx, tran})

  @spec start_mining(pid) :: :ok
  def start_mining(pid), do: GenServer.cast(pid, {:start_mining})

  @spec stop_mining(pid) :: :ok
  def stop_mining(pid), do: GenServer.cast(pid, {:stop_mining})
end

defmodule Bitcoin.NetworkState do
  @type node_states :: %{pid => BtcNodeState.t}
  @type callback :: (NetworkState.t -> {:send, term} | {:sendonce, term} | :nosend | :unregister)
  @type callback_map :: %{atom => callback}

  defstruct states: %{}, callback_maps: %{}
  @type t :: %NetworkState{
    states: node_states,
    callback_maps: %{pid => callback_map},
  }
end

defmodule Bitcoin.Network do
  use GenServer

  @spec start_mining(NetworkState.t) :: NetworkState.t
  def start_mining(state) do
    Enum.each(Map.keys(state.states), fn(pid) -> BtcNode.start_mining(pid) end)
    state
  end

  @spec stop_mining(NetworkState.t) :: NetworkState.t
  def stop_mining(state) do
    Enum.each(Map.keys(state.states), fn(pid) -> BtcNode.stop_mining(pid) end)
    state
  end

  @spec rand_atom() :: atom
  def rand_atom() do
    :rand.uniform(0xFFFFFFFF) |> Integer.to_string |> String.to_atom
  end

  @doc "Get a `callback_tag` which is not being used by `caller`."
  @spec unused_callback_tag(NetworkState.t, pid) :: atom
  def unused_callback_tag(state, caller) do
    callback_tag = rand_atom()
    callbacks = state.callback_maps[caller]
    if nil == callbacks do
      callback_tag
    else
      if Map.has_key?(callbacks, callback_tag) do
        unused_callback_tag(state, caller)
      else
        callback_tag
      end
    end
  end

  ## Server Functions

  @spec do_callbacks(NetworkState.t) :: NetworkState.t
  def do_callbacks(state) do
    Enum.each(state.callback_maps, fn({caller, callback_map}) ->
      Enum.each(callback_map, fn({callback_tag, callback}) ->
        case callback.(state) do
          {:send, payload} -> callback_send(callback_tag, payload, caller)
          {:sendonce, payload} ->
            callback_send(callback_tag, payload, caller)
            unregister_callback(callback_tag, caller)
          :nosend -> nil
          :unregister -> unregister_callback(callback_tag, caller)
          _ -> raise("Invalid return value for callback registered under " <> callback_tag)
        end
      end)
    end)
    state
  end

  @spec init(non_neg_integer) :: {:ok, NetworkState.t}
  def init(num_nodes) do
    # Start all the nodes.
    pids = Enum.map(1..num_nodes, fn(_) -> BtcNode.start_link() end)
    # Set the peers of each node.
    Enum.each(pids, fn(pid) -> BtcNode.set_peers(pid, List.delete(pids, pid)) end)
    # Get the state of each node.
    states = Enum.reduce(pids, %{}, fn(pid, states) ->
      Map.put(states, pid, BtcNode.get_state(pid))
    end)
    {:ok, %NetworkState{states: states} |> start_mining}
  end

  @spec handle_call({:tx, Transaction.t}, GenServer.from, NetworkState.t) :: {:reply, boolean, NetworkState.t}
  def handle_call({:tx, tran}, _from, state) do
    response =
      Enum.random(Map.keys(state.states))
      |> BtcNode.submit_tx(tran)
    {:reply, response, state}
  end

  @spec handle_call({:unused_callback_tag}, GenServer.from, NetworkState.t) :: {:reply, atom, NetworkState.t}
  def handle_call({:unused_callback_tag}, from, state), do: {:reply, unused_callback_tag(state, from), state}

  @spec handle_cast({:node_state_change, pid, BtcNodeState.t}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:node_state_change, from, node_state}, state) do
    state = Map.update!(state, :states, fn(states) ->
      Map.put(states, from, node_state)
    end)
    {:noreply, state |> do_callbacks}
  end

  @spec handle_cast({:register_callback, atom, NetworkState.callback, pid}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:register_callback, callback_tag, callback, caller}, state) do
    state = Map.update!(state, :callback_maps, fn(callback_maps) ->
      Map.update(callback_maps, caller, %{callback_tag => callback}, fn(callbacks) ->
        {_, callbacks} = Map.get_and_update(callbacks, callback_tag, fn(prev_callback) ->
            if prev_callback == nil do
              {nil, callback}
            else
              raise("A callback is already registered under " <> callback_tag)
            end
          end)
        callbacks
      end)
    end)
    {:noreply, state |> do_callbacks}
  end

  @spec handle_cast({:unregister_callback, atom, pid}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:unregister_callback, callback_tag, caller}, state) do
    state = Map.update!(state, :callback_maps, fn(callback_maps) ->
      Map.update!(callback_maps, caller, fn(callbacks) ->
        Map.delete(callbacks, callback_tag)
      end)
    end)
    {:noreply, state}
  end

  @spec handle_cast({:start_mining}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:start_mining}, state), do: {:noreply, start_mining(state)}

  @spec handle_cast({:stop_mining}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:stop_mining}, state), do: {:noreply, stop_mining(state)}

  @spec handle_cast({:stop}, NetworkState.t) :: {:noreply, NetworkState.t}
  def handle_cast({:stop}, state) do
    Enum.each(Map.keys(state.states), fn(pid) -> BtcNode.stop(pid) end)
    {:stop, :normal, state}
  end

  ## Client Functions

  @spec start_link(non_neg_integer) :: pid
  def start_link(num_nodes) do
    {:ok, pid} = GenServer.start_link(__MODULE__, num_nodes, name: __MODULE__)
    pid
  end

  @spec stop() :: :ok
  def stop() do
    GenServer.cast(__MODULE__, {:stop})
  end

  @spec node_state_change(BtcNodeState.t) :: :ok
  def node_state_change(node_state), do: GenServer.cast(__MODULE__, {:node_state_change, self(), node_state})

  @spec register_callback(atom, NetworkState.callback, pid) :: :ok
  def register_callback(callback_tag, callback, caller \\ self()) do
    GenServer.cast(__MODULE__, {:register_callback, callback_tag, callback, caller})
  end

  @spec unregister_callback(atom, pid) :: :ok
  def unregister_callback(callback_tag, caller \\ self()) do
    GenServer.cast(__MODULE__, {:unregister_callback, callback_tag, caller})
  end

  @spec callback_send(atom, term, pid) :: :ok
  def callback_send(atom, payload, caller) do
    Process.send(caller, {atom, payload}, [])
  end

  @spec callback_await(atom) :: term
  def callback_await(atom) do
    receive do
      {^atom, payload} -> payload
    end
  end

  @spec unused_callback_tag() :: atom
  def unused_callback_tag(), do: GenServer.call(__MODULE__, {:unused_callback_tag})

  @spec onetime_callback(fun) :: term
  def onetime_callback(func) do
    callback = fn(net_state) ->
      case func.(net_state) do
        nil -> :nosend
        payload -> {:sendonce, payload}
      end
    end
    callback_tag = unused_callback_tag()
    GenServer.cast(__MODULE__, {:register_callback, callback_tag, callback, self()})
    callback_await(callback_tag)
  end

  @spec submit_tx(Transaction.t) :: boolean
  def submit_tx(tran), do: GenServer.call(__MODULE__, {:tx, tran})

  @spec start_mining() :: :ok
  def start_mining(), do: GenServer.cast(__MODULE__, {:start_mining})

  @spec stop_mining() :: :ok
  def stop_mining(), do: GenServer.cast(__MODULE__, {:stop_mining})
end

defmodule Mix.Tasks.RunNetwork do
  @moduledoc "Run the network with the given number of nodes and never return."
  use Mix.Task

  @spec run([String.t]) :: :ok
  def run(input) do
    num_nodes =
        case Integer.parse(hd(input)) do
          {num_nodes, _} -> num_nodes
          :error -> raise("Invalid input: #{inspect(input)}")
        end
    :observer.start()
    Network.start_link(num_nodes)
    Network.onetime_callback(fn(_net_state) ->
      # Never return
      nil
    end)
  end
end

defmodule Bitcoin do
  @moduledoc """
  The CLI code will go in this module.
  """
end
