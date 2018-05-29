import options, collections

{.passl: "-lsodium".}

const secretboxLength* = 16 + 24
const secretboxKeySize* = 32
type SecretboxKey* = array[32, byte]

proc crypto_secretbox_easy(c: ptr byte, m: ptr byte,
                           mlen: uint64, n: ptr byte,
                           k: ptr byte): cint {.importc.}

proc crypto_secretbox_open_easy(m: ptr byte, c: ptr byte,
                                clen: uint64, n: ptr byte,
                                k: ptr byte): cint {.importc.}

proc secretboxOpen*(key: SecretboxKey, ciphertext: Buffer): Option[Buffer] =
  if ciphertext.len <= secretboxLength:
    return none(Buffer)

  var key = key
  let targetBuf = newBuffer(ciphertext.len - secretboxLength)
  let res = crypto_secretbox_open_easy(addr targetBuf[0], addr ciphertext[24],
                                       uint64(ciphertext.len - 24), addr ciphertext[0], addr key[0])
  if res != 0:
    return none(Buffer)

  return some(targetBuf)

proc secretboxMake*(key: SecretboxKey, plaintext: Buffer, target: Buffer) =
  doAssert(target.len == plaintext.len + secretboxLength)
  let nonceBuf = newView(urandom(24))
  var key = key
  target.copyFrom(nonceBuf)
  doAssert 0 == crypto_secretbox_easy(addr target[24], addr plaintext[0], uint64(plaintext.len),
                                      addr nonceBuf[0], addr key[0])

proc secretboxMake*(key: SecretboxKey, plaintext: Buffer): Buffer =
  ## Pack `plaintext` into secretbox, encrypted and authenticated with `key`.
  let target = newBuffer(plaintext.len + secretboxLength)
  secretboxMake(key, plaintext, target)
  return target

when isMainModule:
  let key = urandom(32).byteArray(32)
  let s = secretboxMake(key, newView("hello"))
  doAssert secretboxOpen(key, s).get.copyAsString == "hello"
