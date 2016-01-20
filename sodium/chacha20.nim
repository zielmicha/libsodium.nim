import sodium/common

type
  ChaCha20Key* = array[32, byte]
  ChaCha20Nonce* = array[8, byte]

proc crypto_stream_chacha20_xor*(c: pointer, m: pointer,
                                 mlen: uint64, n: ptr ChaCha20Nonce,
                                 k: ptr ChaCha20Key): cint {.importc.}

proc chaCha20Xor*(key: ChaCha20Key, nonce: ChaCha20Nonce, data: string): string =
  result = newString(data.len)
  checkzero crypto_stream_chacha20_xor(result.cstring, data.cstring, data.len.uint64,
                                       unsafeAddr(nonce), unsafeAddr(key))
