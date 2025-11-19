from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)


def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i + block_size])
    return blocks


def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block.

    Algorithm:
    1. For each byte position (from last to first)
    2. Try all possible byte values (0-255)
    3. Craft a ciphertext that will produce valid padding if our guess is correct
    4. Use the oracle to test if padding is valid
    5. Calculate the intermediate value and then the plaintext byte
    """
    # Intermediate values (what comes out of AES decryption before XOR with prev block)
    intermediate = bytearray(BLOCK_SIZE)

    # Iterate through each byte position from right to left
    for padding_value in range(1, BLOCK_SIZE + 1):
        # Position we're attacking (0-indexed from left)
        position = BLOCK_SIZE - padding_value

        # Create a modified "previous block" for the oracle query
        crafted_prev = bytearray(BLOCK_SIZE)

        # Set already-known bytes to produce the desired padding
        for i in range(position + 1, BLOCK_SIZE):
            crafted_prev[i] = intermediate[i] ^ padding_value

        # Try all possible values for the current byte
        found = False
        for guess in range(256):
            crafted_prev[position] = guess

            # Construct the test ciphertext: crafted_prev + target_block
            test_ciphertext = bytes(crafted_prev) + target_block

            # Query the oracle
            if padding_oracle(test_ciphertext):
                # Valid padding found!
                # Calculate intermediate value: intermediate = guess XOR padding_value
                intermediate[position] = guess ^ padding_value
                found = True

                # Handle edge case for padding_value == 1
                # Sometimes we might get false positives when padding_value is 1
                # because both 0x01 and 0x02 0x02 are valid
                if padding_value == 1 and position > 0:
                    # Verify by changing a previous byte
                    verify_prev = bytearray(crafted_prev)
                    verify_prev[position - 1] ^= 1
                    test_verify = bytes(verify_prev) + target_block

                    if not padding_oracle(test_verify):
                        # This was a false positive (actual padding was 0x02 0x02, etc.)
                        continue

                break

        if not found:
            raise Exception(f"Failed to find valid byte at position {position}")

    # Calculate plaintext by XORing intermediate with actual previous block
    plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(BLOCK_SIZE))
    return plaintext


def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    print("[*] Starting padding oracle attack...")

    # Split into blocks
    blocks = split_blocks(ciphertext)
    print(f"[*] Total blocks: {len(blocks)}")

    # First block is IV, remaining are ciphertext blocks
    plaintext_blocks = []

    # Decrypt each block (starting from block 1, since block 0 is IV)
    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks) - 1}...", end=" ")

        prev_block = blocks[i - 1]  # Previous block (or IV for first block)
        target_block = blocks[i]  # Block we're decrypting

        decrypted_block = decrypt_block(prev_block, target_block)
        plaintext_blocks.append(decrypted_block)

        print(f"✓")

    # Combine all plaintext blocks
    plaintext = b"".join(plaintext_blocks)
    return plaintext


def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        # PKCS#7 unpadding
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

        # Try to decode as UTF-8
        decoded = unpadded.decode('utf-8')
        return decoded
    except Exception as e:
        print(f"[!] Warning during unpadding/decoding: {e}")
        # Try without unpadding
        try:
            return plaintext.decode('utf-8', errors='replace')
        except:
            return repr(plaintext)


if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f"    Recovered plaintext (raw bytes): {recovered}")
        print(f"    Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\n[+] Final plaintext:")
        print(f"    {decoded}")

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")
        import traceback

        traceback.print_exc()