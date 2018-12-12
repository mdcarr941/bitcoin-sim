# Convert a file encoded in hex to binary.
:io.setopts(:standard_io, encoding: :latin1) # word-around a utf8 binwrite limitation in erlang
Enum.each(IO.stream(:stdio, 4096), fn(str) ->
  IO.binwrite(:stdio, Base.decode16!(str, case: :mixed))
end)
