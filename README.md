## Install dependancies first :
```bash
pip install cryptography colorama numpy time
```

## Download :
```bash
git clone https://github.com/themarcman314/nakamoto_consensus.git
```


## Composition of a block
header
The number of 0's corresponds to the mining difficulty
transactions
nounce : a number that combined with the header and transactions and hashed gives an output starting with a given number of 0's.

(header is the hash of the previous block)
(genesis block has no header)


[video that helped me understand nakamoto's concensus](https://www.youtube.com/watch?v=bBC-nXj3Ng4)
