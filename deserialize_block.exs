# Deserialize the block given on stdin.
{block, <<>>} = File.read!("/dev/stdin") |> Block.deserialize
IO.inspect(block)
