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
        self.number = None # changed this to number from num potentially due to autograder requirements

        self.update_number()

    # Set the transaction number to be SHA256 of self.to_bytes().
    def update_number(self):

        trans_bts = self.to_bytes()
        hash_object = hashlib.sha256()
        hash_object.update(bytes.fromhex(trans_bts))
        
        # .hexdigest() was a function taken from stackoverflow
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
        self.nonce = nonce if nonce is not None else '0' * 16 # we chose 16 as an arbitrary number of 0s, could have been longer
        self.prev = prev

        # proof of wok var
        self.pow = None

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        nonce_num = 0

        # the idea of int(self.hash(), 16) for comparing with difficulty was cited from a python tutorial page
        while int(self.hash(), 16) > DIFFICULTY: # dif comparison as we need to ensure nonce is less than diff
            nonce_num += 1
            self.nonce = f'{nonce_num:016x}'  # 16 total lengt
        self.pow = self.hash()

    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.tx.to_bytes()))
        
        nonce_hex = self.nonce if self.nonce else '0' * 16 # may be able to remove this now as its irrelevant after _init_ update.
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
        for i in block.tx.inputs:
            if i.number not in self.utxos:
                return False  # ensure inputs within utxos otherwise they will have come from nowhere (invalid)

            # this can now be removed for its an input (being spent)
            self.utxos.remove(i.number) 
            

        # adds transaction number to utxos
        self.utxos.append(block.tx.number)
    
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

        # new chain to drop in
        self.chains.append(blockchain)

    # Attempt to append a block broadcast on the network; return true if it is
    # possible to add (e.g. could be a fork). Return false otherwise.
    def append(self, block: Block) -> bool:
        for c in self.chains:
            if self.validBlockChecker(block, c):
                spent_utx = set() # easier for us to use a set here @jason than list
                
                # remove spent - same logic as used in blockchain append (could be refactored?)
                for i in block.tx.inputs:
                    if i.number not in c.utxos or i.number in spent_utx:
                        return False 
                    c.utxos.remove(i.number)
                    spent_utx.add(i.number)

                # add new
                for out in block.tx.outputs:
                    c.utxos.append(block.tx.number)
                c.chain.append(block)
                return True

        # potentially functioning fork logic
        forked_chain = self.fork_Attempt(block)
        if forked_chain:
            self.chains.append(forked_chain)
            return True
    
        print("fork failed")
        return False

    # Build a block on the longest chain you are currently tracking. If the
    # transaction is invalid (e.g. double spend), return None.
    def build_block(self, tx: Transaction) -> Optional[Block]:
        longest_chain = max(self.chains, key=lambda chain: len(chain.chain)) # simplified version cited from python tutorial w3 schools
        
        if not self.validTranChecker(tx, longest_chain):
            return None

        prev_hash = longest_chain.chain[-1].hash() # access prev hash
        new_block = Block(prev_hash, tx, None)
        # necessary step to mine below
        new_block.mine() 
        return new_block
    
    def validTranChecker(self, tx: Transaction, chain: Blockchain, isFork=False) -> bool:
        
        #print(f"valid check for tx {tx.number}")

        iinp_total = 0
        output_sum = sum(out.value for out in tx.outputs)

        used_utxos = set() # set > list for time complexity decrease in look ups
        for ip in tx.inputs:
            # is this a fork? checker
            #if ip.number not in chain.utxos:
                #if isFork:
                    #print(f" {ip.number} but fork")
                    
                #else:
                    #print(f"{ip.number} is not in UTXO")
                    #return False

            if ip.number in used_utxos:
                #print(f"input {ip.number} is already used ")
                #double spend protect
                return False  
            referenced_tx = None
            for block in chain.chain:
                if block.tx.number == ip.number:
                    referenced_tx = block.tx
                    break

            # check existance
            if not referenced_tx:
                return False  # doesnt exist

            # find match
            valid_output_found = False
            for out in referenced_tx.outputs:
                if out.pub_key == ip.output.pub_key and out.value == ip.output.value:
                    valid_output_found = True
                    iinp_total += ip.output.value 
                    break

            if not valid_output_found:
                #no match
                return False 

            # used
            used_utxos.add(ip.number)  

        # for split/merge gradescope requirement
        if iinp_total != output_sum:
            return False  # no mathc

        # verification
        pubkey = tx.inputs[0].output.pub_key
        vkey = VerifyKey(bytes.fromhex(pubkey))
        try:
            vkey.verify(bytes.fromhex(tx.bytes_to_sign()), bytes.fromhex(tx.sig_hex))

        # cited this from the pynacl docs
        except BadSignatureError:
            print("invalid sig")
            return False
        return True




    def validBlockChecker(self, block: Block, chain: Blockchain, isFork=False) -> bool:
        # cited earlier, see block nonce functionality for citation commment
        if int(block.hash(), 16) > DIFFICULTY:
            return False
        if block.prev != chain.chain[-1].hash():
            return False
        if not self.validTranChecker(block.tx, chain, isFork):
            return False
        return True

    def fork_Attempt(self, block: Block) -> Optional[Blockchain]:
        for chain in self.chains:
            for i, existing_block in enumerate(chain.chain):
                if existing_block.hash() == block.prev:
                    # new utxo
                    forked_utxos = set()
                    for j in range(i + 1):
                        forked_utxos.add(chain.chain[j].tx.number)
                        for inp in chain.chain[j].tx.inputs:
                            if inp.number in forked_utxos:
                                forked_utxos.remove(inp.number)
                    new_chain = Blockchain(chain.chain[:i+1].copy(), list(forked_utxos))
                    #print(f"new chan utxo {new_chain.utxos}")
                    if self.validBlockChecker(block, new_chain, isFork=True):
                        if new_chain.append(block):
                            return new_chain
                        #else:
                    #else:
                        #print("not valid for forked")

        return None



# Build and sign a transaction with the given inputs and outputs. If it is
# impossible to build a valid transaction given the inputs and outputs, you
# should return None. Do not verify that the inputs are unspent.
def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    # prototyped logic
    # # Init a transaction has w empty signing key
    # # Bytes to sign = transaction.bytes to sign
    # # Sign bytes using signing key
    # # signature = signing_key.sign(bytes)
    # # Pass in new signature to tx
    # # tx.update_number()
    # # return tx
    
    if not inputs or not outputs:
        return None
    
    # verify
    input_tot = sum(i.output.value for i in inputs)
    output_sum = sum(o.value for o in outputs)
    if input_tot != output_sum:
        return None
    
    # find repeat inputs
    input_numbers = [inp.number for inp in inputs] # cited w3schools python method 
    if len(input_numbers) != len(set(input_numbers)):
        return None

    # Vmatch sign and public key
    vkey = signing_key.verify_key
    expected_pubkey = vkey.encode(encoder=nacl.encoding.HexEncoder).decode()
    
    if not all(i.output.pub_key == expected_pubkey for i in inputs):
        return None  # failed to match

    # start to build transaction rpcoess (no sign to start)
    tx = Transaction(inputs, outputs, "") 

    # sign it
    bytes_to_sign = bytes.fromhex(tx.bytes_to_sign())
    try:
        signature = signing_key.sign(bytes_to_sign).signature.hex()
    # cited from pynacl docs
    except BadSignatureError:
        return None

    tx.sig_hex = signature
    tx.update_number() # update num (this hashes)
    return tx
