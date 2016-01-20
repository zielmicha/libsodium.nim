import sodium/common

const sha512Bytes* = 64

type Sha512Hash* = array[sha512Bytes, byte]

proc crypto_hash_sha512*(output: ptr Sha512Hash,
                        input: pointer,
                        inlen: uint64): cint {.importc.}

proc sha512*(data: string): Sha512Hash =
  checkzero crypto_hash_sha512(addr result, data.cstring, data.len.uint64)

proc sha512d*(data: string): Sha512Hash =
  var partial: Sha512Hash
  checkzero crypto_hash_sha512(addr partial, data.cstring, data.len.uint64)
  checkzero crypto_hash_sha512(addr result, addr partial, sizeof(partial).uint64)

const sha256Bytes* = 32

type Sha256Hash* = array[sha256Bytes, byte]

proc crypto_hash_sha256*(output: ptr Sha256Hash,
                        input: pointer,
                        inlen: uint64): cint {.importc.}

proc sha256*(data: string): Sha256Hash =
  checkzero crypto_hash_sha256(addr result, data.cstring, data.len.uint64)

proc sha256d*(data: string): Sha256Hash =
  var partial: Sha256Hash
  checkzero crypto_hash_sha256(addr partial, data.cstring, data.len.uint64)
  checkzero crypto_hash_sha256(addr result, addr partial, sizeof(partial).uint64)
