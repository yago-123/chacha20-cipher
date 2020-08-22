# ChaCha cipher  
This repo contains the implementation of the chacha cipher created by Daniel J. Bernstein, actually used in the new TLS protocol ([`chacha20 and Poly1305`](https://tools.ietf.org/html/rfc7905)) adopted by Google and OpenSSH in order to replace RC4. 
## Example 
Inside the `cmd` dir can use the ready to run `file_cipher` script: 
```sh 
$ go run file_cipher.go pg-frankenstein.txt
Insert key (32 bytes): 
aW7TjxS6myuDGTSrrRJBUFzv7VKFCFsw
Inset nonce (8 bytes): 
u2YA9JNn
Time taken 0.01 seconds, file length 0.42 MB
Average time 42.61 MB/s 
```
The result file will be avaible with the same name with the termination `.chacha`. In order to decrypt can use the ciphered file with the old parameters used: 
```sh
$ go run file_cipher.go pg-frankenstein.txt.chacha
Insert key (32 bytes): 
aW7TjxS6myuDGTSrrRJBUFzv7VKFCFsw
Inset nonce (8 bytes): 
u2YA9JNn
Time taken 0.01 seconds, file length 0.42 MB
Average time 33.80 MB/s 
```
And now check the signatures: 
```
$ b2sum pg-frankenstein.txt pg-frankenstein.txt.chacha pg-frankenstein.txt.chacha.chacha
89a13cef3d1e6df172faf184d670de05a57f3c8e904633271472b24c7502a9c84d7547de9eae34172b898b02b877189e40760419e17c8b43b7c56ca647a96802  pg-frankenstein.txt
9805a6ec1e4d6af3fd8c144c40612874680ebb84064ef9ce44b5a9984f08624d2e3d1d8dc7bd765b68765ae9e60d234684757f4aa816c4a0167f0445b99ae1da  pg-frankenstein.txt.chacha
89a13cef3d1e6df172faf184d670de05a57f3c8e904633271472b24c7502a9c84d7547de9eae34172b898b02b877189e40760419e17c8b43b7c56ca647a96802  pg-frankenstein.txt.chacha.chacha
```
As you can see the check sum of the first and the last will be the same. 
## Design   
This encryption algorithm belongs to the symmetric key ciphers, the operations that performs are known as ARX (Addition Rotation Xoring). It works xoring plain text with a block of data provided by the user. This explanation will show the basics, for more accurate data check the official [paper](https://cr.yp.to/chacha/chacha-20080128.pdf). 

We can split the explanation in diferent parts: 
- [Chacha Block](#chacha-block) 
- [Quarter Round](#quarter-round)
- [Complete Round](#complete-round) 
- [Xoring](#xoring) 

### Chacha Block 
This block it's one of the keyparts of the operation, it consists in a matrix of 16 integer values (64 characters) and it's formed by 4 different fields: 
- Constant value (4): `"expand 32 byte k"`: 
- Key (8): provided by the user  
- Block Counter (2): numeration of each block  
- Nonce (2): provided by the user 

The length of each can change modifying the size of the others (see that in the paper uses 1 counter and 3 nonces). The constant prevents zero blocks and prevents the attacker surface over the block, it can be found in the code as follows: 
```go
block_t.chachaConst = [4]uint32{ // expand 32 byte k
    1634760805,   // expa
    857760878,    // nd 3
    2036477234,   // 2 by
    1797285236,   // te k
}
```


The set of values is stored in a matrix as follows inside the `block_t` structure: 
```
       cccccccc  cccccccc  cccccccc  cccccccc
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       bbbbbbbb  bbbbbbbb  nnnnnnnn  nnnnnnnn
```
As you can see the block is represented in bytes, but in reality this block is used with int32 values, encoded in little endian.  
### Quarter Round 
One time we have the block, we are going to perform operations over it, the quarter round performs the ARX operations: 
```c
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;
```
Where a, b, c, d correspond to the position of the value in the block, this will change in order to make the complete round, in the package we can see the signature: 
```go
func quarterround(a, b, c, d uint32, input []uint32)
```
### Complete Round 
As the name says, quarter round is only 1/4 of the operation, in order to perform a full round (of the 20 rounds) we will made 4 quarter round. First column by column: 
```go
quarterround(0, 4, 8, 12, input)
quarterround(1, 5, 9, 13, input)
quarterround(2, 6, 10, 14, input)
quarterround(3, 7, 11, 15, input)
```
Then by the diagonals:
```go
quarterround(0, 5, 10, 15, input)
quarterround(1, 6, 11, 12, input)
quarterround(2, 7, 8, 13, input)
quarterround(3, 4, 9, 14, input)
```
For get the 20 rounds we will perform 10 sequential loops.
### Xoring 
One time the block has been treated, we will cipher the plain text with the block with a simple XOR operation: 
```go
for k := 0; k < 16; k++ {
	bufCipher[k] = XOR(bufPlain[k], streamBlock[k])
}
```
Where `bufPlain` is the text that has to be converted (represented in uint32 too) and `streamBlock` is the block created/treated build from the constant, counter block and the key/nonce provided by the user. In order to perform the decipher operation we will perform the same operation of the cipher because of the symmetric nature of the algorithm.  
## Number of rounds
The number of rounds aren't a random number, the chacha design is contempled to use rounds of 8, 12 or 20 being the last the slowest, in the actuality, all of them are a secure option, can change the rounds of the package with the constant `NUMBER_ROUNDS`