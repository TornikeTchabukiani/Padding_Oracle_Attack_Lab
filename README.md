# Padding Oracle Attack Lab Report

## Task 1: Understanding the Components

### 1. How does the padding_oracle function determine if padding is valid?

The `padding_oracle` function determines padding validity through these steps:

1. **Block size check**: First verifies that the ciphertext length is a multiple of the block size (16 bytes)
2. **Decryption**: Extracts the IV and ciphertext, then decrypts using AES-CBC
3. **Padding validation**: Attempts to unpad using PKCS#7 unpadder
4. **Return value**: Returns `True` if unpadding succeeds, `False` if it raises a `ValueError` or `TypeError`

The key insight is that the function **leaks information** about whether padding is valid - this is the "oracle" that makes the attack possible.

### 2. What is the purpose of the IV in CBC mode?

The Initialization Vector (IV) serves several purposes in CBC mode:

- **Randomization**: Ensures that identical plaintexts produce different ciphertexts
- **XOR operation**: For the first block, the plaintext is XORed with the IV before encryption
- **Chaining**: For subsequent blocks, each plaintext block is XORed with the previous ciphertext block

**CBC Decryption Formula**:
```
Plaintext[0] = Decrypt(Ciphertext[0]) ⊕ IV
Plaintext[i] = Decrypt(Ciphertext[i]) ⊕ Ciphertext[i-1]
```

### 3. Why does the ciphertext need to be a multiple of the block size?

Block ciphers like AES operate on fixed-size blocks (16 bytes for AES). This requirement exists because:

- AES can only encrypt/decrypt complete 16-byte blocks
- If the ciphertext length isn't a multiple of 16, it means data is corrupted or incomplete
- PKCS#7 padding ensures the plaintext is padded to a multiple of the block size before encryption

---

## Task 2-5: Implementation Details

### How the Padding Oracle Attack Works

The attack exploits the padding oracle to decrypt ciphertext **without knowing the key**. Here's the core principle:

#### CBC Decryption Process:
```
Intermediate = AES_Decrypt(Ciphertext_Block)
Plaintext = Intermediate ⊕ Previous_Ciphertext_Block
```

#### Attack Strategy:

1. **Control the previous block**: We can modify the "previous block" to control what gets XORed with the intermediate value
2. **Test padding validity**: By trying different byte values, we can determine when valid padding occurs
3. **Deduce intermediate value**: When padding is valid, we know the relationship between our crafted byte and the intermediate value
4. **Calculate plaintext**: Once we have the intermediate value, we can XOR it with the actual previous block to get plaintext

#### Byte-by-Byte Process:

For a block with valid padding value of `0x01`:
```
Crafted_Byte ⊕ Intermediate = 0x01
Therefore: Intermediate = Crafted_Byte ⊕ 0x01
And: Plaintext_Byte = Intermediate ⊕ Actual_Previous_Block_Byte
```

### Key Implementation Challenges

1. **Edge case for padding value 1**: When searching for the last byte, a false positive can occur if the actual padding is `0x02 0x02` instead of `0x01`. Solution: Verify by changing a previous byte.

2. **Building the crafted block**: For each padding value, we must set all already-discovered bytes to produce the desired padding pattern.

3. **Iteration order**: We attack bytes from right to left (end to beginning) because PKCS#7 padding starts from the end.

---

## Attack Visualization

### Example: Decrypting the last byte

```
Target Block: [?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??]
Previous Block: [C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF]

Step 1: Find byte that produces padding 0x01
Crafted Prev: [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 XX]

Try XX = 0x00, 0x01, 0x02... until oracle returns True

Say oracle returns True when XX = 0x7A:
Intermediate[15] = 0x7A ⊕ 0x01 = 0x7B
Plaintext[15] = 0x7B ⊕ CF (actual previous block byte)
```

### Example: Decrypting second-to-last byte

```
Now we know Intermediate[15] = 0x7B

Step 2: Find byte that produces padding 0x02 0x02
Crafted Prev: [00 00 00 00 00 00 00 00 00 00 00 00 00 00 YY (0x7B⊕0x02)]

The last byte is set to: 0x7B ⊕ 0x02 = 0x79
This ensures last byte decrypts to 0x02

Try YY = 0x00, 0x01, 0x02... until oracle returns True
```

---

## Security Implications

### Why This Attack is Devastating:

1. **No key needed**: Attacker can decrypt without knowing the encryption key
2. **Common vulnerability**: Many systems historically leaked padding information
3. **Practical impact**: Affects TLS, web applications, and encrypted databases

### Real-World Examples:

- **ASP.NET vulnerability (2010)**: Padding oracle in ViewState encryption
- **TLS BEAST attack**: Exploited CBC mode weaknesses
- **Java web frameworks**: Various implementations leaked padding errors

### Mitigation Strategies:

1. **Use authenticated encryption**: AES-GCM, ChaCha20-Poly1305
2. **Constant-time operations**: Don't leak timing information
3. **MAC-then-Encrypt**: Verify MAC before decrypting
4. **Generic error messages**: Never distinguish between padding and MAC errors

---

## Lab Observations

### Challenges Faced:

1. **Understanding XOR relationships**: Drawing out the CBC decryption helped visualize the XOR chains
2. **Handling the padding value 1 edge case**: Required additional verification step
3. **Performance**: Attacking each byte requires up to 256 oracle queries

### Performance Analysis:

- Blocks to decrypt: 4 (64 bytes total)
- Bytes per block: 16
- Max queries per byte: 256
- **Worst case**: 4 × 16 × 256 = 16,384 queries
- **Typical case**: 4 × 16 × 128 = 8,192 queries (average)

### Key Insights:

1. The attack is **deterministic** - it will always succeed given a padding oracle
2. Modern systems should **never** expose padding validity
3. **Authenticated encryption** is the correct solution
4. This demonstrates why **side channels** are critical security concerns

---

## Conclusion

The padding oracle attack demonstrates a fundamental principle in cryptography: **encryption alone is not enough**. The system must not leak any information about the internal state, including whether padding is valid.

This lab reinforced:
- How CBC mode works mathematically
- The importance of constant-time implementations
- Why authenticated encryption modes are preferred
- How a small information leak can completely break encryption

**Key Takeaway**: Always use authenticated encryption modes (like AES-GCM) that provide both confidentiality and integrity, and never expose implementation details through error messages or timing differences.
