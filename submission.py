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
        self.nonce = nonce if nonce is not None else '0' * 16
        self.prev = prev
        self.pow = None

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        nonce_int = 0
        while int(self.hash(), 16) > DIFFICULTY:
            nonce_int += 1
            self.nonce = f'{nonce_int:016x}'  # 16 total lengt
        self.pow = self.hash()

    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.tx.to_bytes()))
        
        nonce_hex = self.nonce if self.nonce else '0' * 16
        # print(f"Nonce (hex): {nonce_hex}")  # debug
        m.update(bytes.fromhex(nonce_hex))

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
        for inp in block.tx.inputs:
            if inp.number not in self.utxos:
                return False  # Reject the block if any input is not in the UTXO set
            self.utxos.remove(inp.number)

        # Add the new output to the UTXO set
        self.utxos.append(block.tx.number)
        
        # Finally, append the block to the chain
        self.chain.append(block)
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
        utxos = [genesis.tx.number]  
        # this above ment to track utxo of genesis
        blockchain = Blockchain([genesis], utxos)
        self.chains.append(blockchain)

    # Attempt to append a block broadcast on the network; return true if it is
    # possible to add (e.g. could be a fork). Return false otherwise.
    def append(self, block: Block) -> bool:
        for chain in self.chains:
            if self.validBlockChecker(block, chain):
                used_utxos = set()
                
                # Remove all inputs (spent UTXOs) from the UTXO set
                for inp in block.tx.inputs:
                    if inp.number not in chain.utxos or inp.number in used_utxos:
                        return False  # Reject if the UTXO doesn't exist or was already used in this block
                    chain.utxos.remove(inp.number)
                    used_utxos.add(inp.number)

                # Add all outputs (new UTXOs) to the UTXO set
                for out in block.tx.outputs:
                    chain.utxos.append(block.tx.number)

                # Append the block to the chain
                chain.chain.append(block)
                return True

        print("No valid chain found. Attempting to fork...")
        forked_chain = self._fork_chain(block)
        if forked_chain:
            print("Forking successful. New chain created.")
            self.chains.append(forked_chain)
            return True
    
        print("Forking failed. Block cannot be appended.")
        return False



    # Build a block on the longest chain you are currently tracking. If the
    # transaction is invalid (e.g. double spend), return None.
    def build_block(self, tx: Transaction) -> Optional[Block]:
        longest_chain = max(self.chains, key=lambda chain: len(chain.chain))
        
        if not self.validTranChecker(tx, longest_chain):
            return None

        prev_hash = longest_chain.chain[-1].hash()
        new_block = Block(prev_hash, tx, None)
        new_block.mine()
        return new_block
    
    def validTranChecker(self, tx: Transaction, chain: Blockchain, is_fork=False) -> bool:
        # Debugging information
        print(f"Checking validity of transaction with number: {tx.number}")
        print(f"UTXO set: {chain.utxos}")
        print(f"Transaction inputs: {[(inp.number, inp.output.value) for inp in tx.inputs]}")
        print(f"Transaction outputs: {[(out.value, out.pub_key) for out in tx.outputs]}")

        input_sum = 0
        output_sum = sum(out.value for out in tx.outputs)

        used_utxos = set()

        # Iterate over each input in the transaction
        for inp in tx.inputs:
            # If the transaction is part of a fork, allow inputs that are not in the UTXO set
            if inp.number not in chain.utxos:
                if is_fork:
                    print(f"Input {inp.number} not in UTXO set, but allowing it for fork")
                else:
                    print(f"Input {inp.number} is not in UTXO set")
                    return False

            if inp.number in used_utxos:
                print(f"Input {inp.number} is already used in this transaction")
                return False  # Reject double-spent inputs

            # Find the referenced transaction in the blockchain
            referenced_tx = None
            for block in chain.chain:
                if block.tx.number == inp.number:
                    referenced_tx = block.tx
                    break

            # Check if the referenced transaction exists
            if not referenced_tx:
                print(f"Referenced transaction {inp.number} does not exist")
                return False  # Reject if the referenced transaction doesn't exist

            # Ensure the referenced transaction's output matches the input's provided public key and value
            valid_output_found = False
            for out in referenced_tx.outputs:
                if out.pub_key == inp.output.pub_key and out.value == inp.output.value:
                    valid_output_found = True
                    input_sum += inp.output.value  # Add to input sum if valid
                    break

            if not valid_output_found:
                print(f"Referenced output for input {inp.number} does not match")
                return False  # Reject if the referenced output does not match

            used_utxos.add(inp.number)  # Mark this UTXO as used for this transaction

        # Ensure input sum equals output sum for UTXO splitting/merging
        if input_sum != output_sum:
            print(f"Input sum ({input_sum}) does not match output sum ({output_sum})")
            return False  # Reject if the sums don't match

        # Verify the transaction's signature
        pubkey = tx.inputs[0].output.pub_key
        verify_key = VerifyKey(bytes.fromhex(pubkey))
        try:
            verify_key.verify(bytes.fromhex(tx.bytes_to_sign()), bytes.fromhex(tx.sig_hex))
        except BadSignatureError:
            print("Invalid signature")
            return False

        print("Transaction is valid")
        return True




    def validBlockChecker(self, block: Block, chain: Blockchain, is_fork=False) -> bool:
        print(f"Checking validity of block with prev hash: {block.prev}")
        print(f"Block hash: {block.hash()}")
        print(f"Difficulty: {DIFFICULTY}")
        print(f"Last block hash in chain: {chain.chain[-1].hash()}")
    
        if int(block.hash(), 16) > DIFFICULTY:
            print("Block hash does not meet difficulty requirement")
            return False
        if block.prev != chain.chain[-1].hash():
            print(f"Block prev hash {block.prev} does not match last block hash {chain.chain[-1].hash()}")
            return False
        if not self.validTranChecker(block.tx, chain, is_fork):
            print("Transaction in block is not valid")
            return False
        print("Block is valid")
        return True

    def _fork_chain(self, block: Block) -> Optional[Blockchain]:
        print(f"Attempting to fork chain for block with prev hash: {block.prev}")
        for chain in self.chains:
            for i, existing_block in enumerate(chain.chain):
                if existing_block.hash() == block.prev:
                    print(f"Found matching block at index {i} in chain")
                    # Create a new UTXO set up to the fork point
                    forked_utxos = set()
                    for j in range(i + 1):
                        forked_utxos.add(chain.chain[j].tx.number)
                        for inp in chain.chain[j].tx.inputs:
                            if inp.number in forked_utxos:
                                forked_utxos.remove(inp.number)
                    new_chain = Blockchain(chain.chain[:i+1].copy(), list(forked_utxos))
                    print(f"New chain length: {len(new_chain.chain)}")
                    print(f"New chain UTXO set: {new_chain.utxos}")
                    if self.validBlockChecker(block, new_chain, is_fork=True):
                        print("Block is valid for the new forked chain")
                        if new_chain.append(block):
                            print("Block successfully appended to new chain")
                            return new_chain
                        else:
                            print("Failed to append block to new chain")
                    else:
                        print("Block is not valid for the new forked chain")
        print("No valid fork found")
        return None



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
