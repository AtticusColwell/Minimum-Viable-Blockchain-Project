import hashlib
import random
from typing import List, Optional
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import nacl.encoding


DIFFICULTY = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

"""
Please do not modify any of the signatures on the classes below so the
autograder can properly run your submission. You are free (and encouraged!) to
add additional data members as you implement these functions.
"""

class Output:
    """
    A transaction output.
    """

    def __init__(self, value: int, pub_key: str):
        self.value = value
        self.pub_key = pub_key

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(4, 'big', signed=False) + bytes.fromhex(self.pub_key)

class Input:
    """
    A transaction input. The number refers to the transaction number where the
    input was generated (see `Transaction.update_number()`).
    """

    def __init__(self, output: Output, number: str):
        self.output = output
        self.number = number

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.output.to_bytes() + bytes.fromhex(self.number)


class Transaction:
    """
    A transaction in a block. A signature is the hex-encoded string that
    represents the bytes of the signature.
    """

    def __init__(self, inputs: List[Input], outputs: List[Output], sig_hex: str):
        self.inputs = inputs
        self.outputs = outputs
        self.sig_hex = sig_hex
        self.number = None

        self.update_number()

    # Set the transaction number to be SHA256 of self.to_bytes().
    def update_number(self):

        trans_bytes = self.to_bytes()
        hash_object = hashlib.sha256()
        
        hash_object.update(bytes.fromhex(trans_bytes))
        
        self.number = hash_object.hexdigest()

    # Get the bytes of the transaction before signatures; signers need to sign
    # this value!
    def bytes_to_sign(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()

        return m.hex()
    
    def to_bytes(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()

        m += bytes.fromhex(self.sig_hex)

        return m.hex()
    
class Block:
    """
    A block on a blockchain. Prev is a string that contains the hex-encoded hash
    of the previous block.
    """

    def __init__(self, prev: str, tx: Transaction, nonce: Optional[str]):
        self.tx = tx
        self.nonce = nonce
        self.prev = prev
        self.pow = None

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        self.nonce = 0
        while int(self.hash(), 16) > DIFFICULTY:
            self.nonce += 1
            self.nonce = hex(self.nonce)[2:]
        
        self.nonce = str(self.nonce)
        self.pow = self.hash()

    
    # Hash the block.
    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(str(self.prev)))
        m.update(bytes.fromhex(str(self.tx.to_bytes())))
        m.update(bytes.fromhex(str(self.nonce)))

        return m.hexdigest()
    
class Blockchain:
    """
    A blockchain. This class is provided for convenience only; the autograder
    will not call this class.
    """
    
    def __init__(self, chain: List[Block], utxos: List[str]):
        self.chain = chain
        self.utxos = utxos
    
    def append(self, block: Block) -> bool:
        # Check proof work
        if int(block.hash(), 16) > DIFFICULTY:
            return False

         # Check if previous block hash matches the last block in the chain
        last_block = self.chain[-1]
        if block.prev != last_block.hash():
            return False
        
        # Append the block and update UTXOs
        self.chain.append(block)
        for inp in block.tx.inputs:
            if inp.number in self.utxos:
                self.utxos.remove(inp.number)
        for out in block.tx.outputs:
            self.utxos.append(block.tx.number)
        
        return True

class Node:
    """
    All chains that the node is currently aware of.
    """
    def __init__(self):
        # We will not access this field, you are free change it if needed.
        self.chains = []

    # Create a new chain with the given genesis block. The autograder will give
    # you the genesis block.
    def new_chain(self, genesis: Block):
        blockchain = Blockchain([genesis], [])
        self.chains.append(blockchain)

    # Attempt to append a block broadcast on the network; return true if it is
    # possible to add (e.g. could be a fork). Return false otherwise.
    def append(self, block: Block) -> bool:
        for chain in self.chains:
            if chain.append(block):
                return True
        return False

    # Build a block on the longest chain you are currently tracking. If the
    # transaction is invalid (e.g. double spend), return None.
    def build_block(self, tx: Transaction) -> Optional[Block]:
        # Find the longest chain
        longest_chain = max(self.chains, key=lambda chain: len(chain.chain))
        
        # Validate that no double spending occurs
        #for inp in tx.inputs:
            #if inp.number not in longest_chain.utxos:
                #return None  # Invalid transaction, double spend
        
        # Create a new block with the transaction
        prev_hash = longest_chain.chain[-1].hash()
        new_block = Block(prev_hash, tx, None)
        new_block.mine()  # Perform proof-of-work
        return new_block

# Build and sign a transaction with the given inputs and outputs. If it is
# impossible to build a valid transaction given the inputs and outputs, you
# should return None. Do not verify that the inputs are unspent.
def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:

    # # Init a transaction has w empty signing key
    # tx = Transaction(inputs, outputs, "")
    # # Bytes to sign = transaction.bytes to sign
    # bytes = tx.bytes_to_sign()
    # # Sign bytes using signing key
    # signature = signing_key.sign(bytes)
    # # Pass in new signature to tx
    # tx.sig_hex = signature
    # tx.update_number()
    # return tx

    if not inputs or not outputs:
        return None
    
    # Verify input sum equals output sum
    input_sum = sum(inp.output.value for inp in inputs)
    output_sum = sum(out.value for out in outputs)
    if input_sum != output_sum:
        return None
    
    # Check for duplicate inputs
    input_numbers = [inp.number for inp in inputs]
    if len(input_numbers) != len(set(input_numbers)):
        return None

    # Verify that all inputs have the same public key, matching the signing key
    verify_key = signing_key.verify_key
    expected_pubkey = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    
    if not all(inp.output.pub_key == expected_pubkey for inp in inputs):
        return None  # Inputs don't match the signing key

    # Create transaction with empty signature
    tx = Transaction(inputs, outputs, "")

    # Sign the transaction
    bytes_to_sign = bytes.fromhex(tx.bytes_to_sign())
    try:
        signature = signing_key.sign(bytes_to_sign).signature.hex()
    except BadSignatureError:
        return None

    # Update transaction with signature and number
    tx.sig_hex = signature
    tx.update_number()

    return tx

