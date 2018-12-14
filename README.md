## Features Implemented, Part 1

Bitcoin mining, transactions, and wallet functionality have all been implemented.
There are many unit tests in the file `test/bitcoin_test.exs` verifying the 
correctness of this implementation. Most of these were taken from the bitcoin wiki,
stackoverflow, or the bitcoin.org documentation.
For a more complete test of the above functionality take a look at the very last test
(`Transactions`), which exercises all of these features.

An extra feature which was implemented is the script `deserialize_block.exs` which allows
you to dump information about a serialize bitcoin block to the console. I've included
block 170 in the file `blk170.bin`. You can deserialize it to see its contents by running
`mix run deserialize_block.exs < blk170.exs` from the project directory.

## Features Implemented, Part 2

A web interface showing the distribution of bitcoins in the network, how many are in circulation,
and the length of the shortest and longest chains in the network (these will be equal most of the
time). You can also request the private key of any node in the network. This was added in preparation
to do the bonus, which was not completed in time.

## Running

Simply call `mix test` from the project directory to run the test suite.

To run the web server invoke `mix phx.server` then point your web browser at
`http://localhost:4000/`.
