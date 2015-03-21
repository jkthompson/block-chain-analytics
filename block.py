import struct
import hashlib

magic_number = 0xD9B4BEF9
block_prefix_format = 'I32s32sIII'

def read_uint1(stream):
    return ord(stream.read(1))

def read_uint2(stream):
    return struct.unpack('H', stream.read(2))[0]

def read_uint4(stream):
    return struct.unpack('I', stream.read(4))[0]

def read_uint8(stream):
    return struct.unpack('Q', stream.read(8))[0]

def read_hash32(stream):
   return stream.read(32)[::-1] #reverse it since we are little endian

def read_merkle32(stream):
   return stream.read(32)[::-1] #reverse it

def read_time(stream):
   utctime = read_uint4(stream)
   #Todo: convert to datetime object
   return utctime

def read_varint(stream):
   ret = read_uint1(stream)

   if ret < 0xfd: #one byte int
      return ret
   if ret == 0xfd: #unit16_t in next two bytes
      return read_uint2(stream)
   if ret == 0xfe: #uint32_t in next 4 bytes
      return read_uint4(stream)
   if ret == 0xff: #uint42_t in next 8 bytes
      return read_uint8(stream)
   return -1

def get_hexstring(bytebuffer):
   #return ''.join(('%x'%ord(a)) for a in bytebuffer)
   return bytebuffer.encode('hex')


def find_magic_number(stream):
   '''read byte stream until a magic number is found, returns None if end of stream is reached'''
   while True:
       byte = stream.read(1)
       if not byte: return None # EOF
       if (ord(byte) == 0xf9):
           stream.seek(-1,1) # move back 1 byte and try to read all 4 bytes
           magic = read_uint4(stream)
           if (magic == 0xd9b4bef9):
               return magic


class Tx_Input(object):
   def __init__(self):
      super(Tx_Input, self).__init__()

   def parse(self, stream):
      self.prevhash = read_hash32(stream)
      self.prevtx_out_idx = read_uint4(stream)
      self.txin_script_len = read_varint(stream)
      # TODO in later modules we will convert scriptSig to its own class
      self.scriptSig = stream.read(self.txin_script_len)
      self.sequence_no = read_uint4(stream)

   def updateTxDict(self,txDict):
       '''txDict holds arrays of Tx_Input values'''
       txDict['txIn_prevhash'] = txDict.get('txIn_prevhash', [])
       txDict['txIn_prevhash'].append(get_hexstring(self.prevhash))

       txDict['txIn_prevtx_out_idx'] = txDict.get('txIn_prevtx_out_idx', [])
       txDict['txIn_prevtx_out_idx'].append(self.prevtx_out_idx)

       txDict['txIn_txin_script_len'] = txDict.get('txIn_txin_script_len', [])
       txDict['txIn_txin_script_len'] .append(self.txin_script_len)

       txDict['txIn_scriptSig'] = txDict.get('txIn_scriptSig', [])
       txDict['txIn_scriptSig'].append(get_hexstring(self.scriptSig))

       txDict['txIn_sequence_no'] = txDict.get('txIn_sequence_no', [])
       txDict['txIn_sequence_no'].append(self.sequence_no)

       return txDict

   def __str__(self):
      return 'PrevHash: %s \nPrev Tx out index: %d \nTxin Script Len: %d \nscriptSig: %s \nSequence: %8x' % \
               (get_hexstring(self.prevhash),
                self.prevtx_out_idx,
                self.txin_script_len,
                get_hexstring(self.scriptSig),
                self.sequence_no)

   def __repr__(self):
      return __str__(self)


class Tx_Output(object):
   def __init__(self):
      super(Tx_Output, self).__init__()
      pass

   def parse(self, stream):
      self.value = read_uint8(stream)
      self.txout_script_len = read_varint(stream)
      self.scriptPubKey = stream.read(self.txout_script_len)

   def updateTxDict(self,txDict):
       '''txDict holds arrays of Tx_Output values'''
       txDict['txOut_value'] = txDict.get('txOut_value', [])
       txDict['txOut_value'].append(self.value)

       txDict['txOut_script_len'] = txDict.get('txOut_script_len', [])
       txDict['txOut_script_len'].append(self.txout_script_len)

       txDict['txOut_scriptPubKey'] = txDict.get('txOut_scriptPubKey', [])
       txDict['txOut_scriptPubKey'].append(get_hexstring(self.scriptPubKey))

       return txDict

   def __str__(self):
      return 'Value (satoshis): %d (%f btc)\nTxout Script Len: %d\nscriptPubKey: %s' %\
               (self.value, (1.0*self.value)/100000000.00,
                self.txout_script_len,
                get_hexstring(self.scriptPubKey))

   def __repr__(self):
      return __str__(self)


class Transaction(object):
   """Holds one Transaction as part of a block"""
   def __init__(self):
      super(Transaction, self).__init__()
      self.version = None
      self.in_cnt = None
      self.inputs = None
      self.out_cnt = None
      self.outputs = None
      self.lock_time = None

   def parse(self,stream):
      #TODO: error checking
      self.version = read_uint4(stream)
      self.in_cnt = read_varint(stream)
      self.inputs = []
      if self.in_cnt > 0:
         for i in range(0, self.in_cnt):
            input = Tx_Input()
            input.parse(stream)
            self.inputs.append(input)
      self.out_cnt = read_varint(stream)
      self.outputs = []
      if self.out_cnt > 0:
         for i in range(0, self.out_cnt):
            output = Tx_Output()
            output.parse(stream)
            self.outputs.append(output)
      self.lock_time = read_uint4(stream)

   def updateTxDict(self,txDict):
       txDict['tx_version'] = self.version
       txDict['in_cnt'] = self.in_cnt
       txDict['out_cnt'] = self.out_cnt
       txDict['lock_time'] = self.lock_time
       for i in range(self.in_cnt):
          txDict = self.inputs[i].updateTxDict(txDict)
       for i in range(self.out_cnt):
          txDict = self.outputs[i].updateTxDict(txDict)
       return txDict


   def __str__(self):
      s = 'Version: %d\nInputs count: %d\n---Inputs---\n%s\nOutputs count: %d\n---Outputs---\n%s\nLock_time:%8x' % (self.version, self.in_cnt,
               '\n'.join(str(i) for i in self.inputs),
               self.out_cnt,
               '\n'.join(str(o) for o in self.outputs),
               self.lock_time)
      return s


class BlockHeader(object):
   """BlockHeader represents the header of the block"""
   def __init__(self):
      super( BlockHeader, self).__init__()
      self.version = None
      self.prevhash = None
      self.merklehash = None
      self.time = None
      self.bits = None
      self.nonce = None
      self.blockprefix = None
      self.blockhash = None

   def parse(self, stream):
      #TODO: error checking
      self.version = read_uint4(stream)
      self.prevhash = read_hash32(stream)
      self.merklehash = read_merkle32(stream)
      self.time = read_time(stream)
      self.bits = read_uint4(stream)
      self.nonce = read_uint4(stream)

      # construct the prefix and hash
      self.blockprefix = ( struct.pack("<L", self.version) + self.prevhash[::-1] + \
            self.merklehash[::-1] + struct.pack("<LLL", self.time, self.bits, self.nonce))
      self.blockhash = hashlib.sha256(hashlib.sha256(self.blockprefix).digest()).digest()[::-1]

   def updateTxDict(self, txDict):
       txDict['version'] = self.version
       txDict['prevhash'] = get_hexstring(self.prevhash)
       txDict['merklehash'] = get_hexstring(self.merklehash)
       txDict['time'] = self.time
       txDict['bits'] = self.bits
       txDict['nonce'] = self.nonce
       txDict['blockprefix'] = get_hexstring(self.blockprefix)
       txDict['blockhash'] = get_hexstring(self.blockhash)
       return txDict


   def __str__(self):
      return "\n\t\tVersion: %d \n\t\tPreviousHash: %s \n\t\tMerkle: %s \n\t\tTime: %8x \n\t\tBits: %8x \n\t\tNonce: %8x \n\t\tPrefix: %s \n\t\tBlockHash: %s \n\t\t" % (self.version, \
               get_hexstring(self.prevhash), \
               get_hexstring(self.merklehash), \
               self.time, \
               self.bits, \
               self.nonce, \
               get_hexstring(self.blockprefix), \
               get_hexstring(self.blockhash))

   def __repr__(self):
      return __str__(self)


class Block(object):
   """A block to be parsed from file"""
   def __init__(self):
       self.magic_no = -1
       self.blocksize = 0
       self.blockheader = None
       self.transaction_cnt = 0
       self.transactions = None

   def parseBlock(self, bf):
       self.magic_no = find_magic_number(bf)
       if self.magic_no != None:
           self.blocksize = read_uint4(bf)
           self.blockheader = BlockHeader()
           self.blockheader.parse(bf)
           self.transaction_cnt = read_varint(bf)
           self.transactions = []
           #print 'List of transactions'
           for i in range(0, self.transaction_cnt):
               tx = Transaction()
               tx.parse(bf)
               self.transactions.append(tx)

   def printBlock(self):
        print 'magic_no:\t0x%8x' % self.magic_no
        print 'size:    \t%u bytes' % self.blocksize
        print 'Block header:\t%s' % self.blockheader
        print 'Transactions: \t%d' % self.transaction_cnt
        for i in range(0, self.transaction_cnt):
            print '='*50
            print ' TX NUMBER: %d' % (i+1)
            print '='*50
            print self.transactions[i]
            print '\n'


   def updateTxDict(self,idx,txDict):
       '''Return data for a specific transaction as a dict'''
       '''Each transaction record will also contain all information about the block as well'''
       txDict['magic_no'] = self.magic_no
       txDict['blocksize'] = self.blocksize
       txDict['transaction_cnt'] = self.transaction_cnt
       txDict = self.blockheader.updateTxDict(txDict)
       txDict = self.transactions[idx].updateTxDict(txDict)
       return txDict

   def getBlockHash(self):
        return get_hexstring(self.blockheader.blockhash)

   def getBlockPrevHash(self):
        return get_hexstring(self.blockheader.prevhash)

   def getBlockDifficulty(self):
        return self.blockheader.bits

   def getNumTxs(self):
       return self.transaction_cnt

def parseBlockBytes(bytestream):
    blocks = []
    count = 0;
    while True:
        curBlock = Block()
        curBlock.parseBlock(bytestream)
        if (curBlock.blocksize == 0):
            break
        else:
            blocks.append(curBlock)
    return blocks

def parseBlockFile(blockfile):
    with open(blockfile, 'rb') as bf:
        blocks = parseBlockBytes(bf)
    return blocks

def printBlockFile(blockfile):
    print 'Parsing block file: %s\n' % blockfile
    blocks = parseBlockFile(blockfile)
    count = 0;
    for blk in blocks:
        count = count + 1
        print("Block Count: " + str(count))
        blk.printBlock()


if __name__ == "__main__":
   import sys
   usage = "Usage: python {0} "
   if len(sys.argv) < 2:
      print usage.format(sys.argv[0])
   else:
      parseBlockFile(sys.argv[1])
