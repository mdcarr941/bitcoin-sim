# Encode binary input as hex.
:io.setopts(:standard_io, encoding: :latin1) # word-around a utf8 binwrite limitation in erlang
Enum.each(IO.binstream(:stdio, 4096), fn(data) ->
  IO.write(:stdio, Base.encode16(data, case: :lower))
end)
