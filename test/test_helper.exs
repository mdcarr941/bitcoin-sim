ExUnit.start()

defmodule Bitcoin.Tests.Helpers do
  @moduledoc "Functions to help with testing."
  import ExUnit.Assertions
  alias Bitcoin.Serialize
  alias Bitcoin.TxOut
  alias Bitcoin.OutPoint
  alias Bitcoin.TxIn
  alias Bitcoin.Transaction
  alias Bitcoin.Crypto
  alias Bitcoin.Script

  def pub_priv() do
    int = 0xf19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4
    priv_key = Serialize.to_big_end_unsigned(int, 32)
    pub_key = Crypto.key_gen(priv_key)
    {pub_key, priv_key}
  end

  @doc "Got this from http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html"
  @spec address() :: String.t
  def address() do
    "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa"
  end

  def test_hash(), do: :crypto.hash(:sha256, "The meaning of life is (char)42 == '*'.")

  def test_out_point(), do: %OutPoint{hash: test_hash(), index: 1}

  def test_tx_in() do
    out_point = test_out_point()
    {pub_key, _} = pub_priv()
    TxIn.new(out_point, "signature", pub_key)
  end

  def assert_out_points_equal(left, right) do
    assert left.hash == right.hash
    assert left.index == right.index
  end

  @spec assert_scripts_equal(Script.t, Script.t) :: nil
  def assert_scripts_equal(left, right) do
    left_len = length(left)
    assert left_len == length(right)
    Enum.each(0..left_len-1, fn(index) ->
      assert Enum.at(left, index) == Enum.at(right, index)
    end)
  end

  def test_tx_out(), do: TxOut.new(712, address())

  @spec assert_tx_out_equal(TxOut.t, TxOut.t) :: nil
  def assert_tx_out_equal(left, right) do
    assert left.value == right.value
    assert_scripts_equal(left.pk_script, right.pk_script)
  end

  @doc "Assert the two `%TxIn{}` structs are equal."
  def assert_tx_in_equal(left, right) do
    assert_out_points_equal(left.prev_out, right.prev_out)
    assert_scripts_equal(left.sig_script, right.sig_script)
    assert left.sequence == right.sequence
  end

  @doc "This test case is from https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx"
  def transaction_test_case() do
    out_point = %OutPoint{
      # This is the hash of the transaction we're claiming one of the outputs of.
      hash: Serialize.from_hex("eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2"),
      index: 1
    }
    tx_in = %TxIn{prev_out: out_point}
    # This is the pk_script for the key that we're giving the bitcoins to.
    {out_script, <<>>} = Script.decompile(Serialize.from_hex("76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"))
    tx_out = %TxOut{value: 99900000, pk_script: out_script}
    trans = %Transaction{tx_in: [tx_in], tx_out: [tx_out]}

    # The pk_script of the previous transaction output we're trying to spend.
    {prev_pk_script, <<>>} = Script.decompile(Serialize.from_hex("76a914010966776006953d5567439e5e39f86a0d273bee88ac"))

    # This is the private key which is able to claim the transaction being spent.
    priv_key = Serialize.from_hex("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")

    {trans, prev_pk_script, priv_key}
  end
end
