import collections, sodium/sha2

type
  C25519Public* = array[32, byte]
  C25519Private* = array[64, byte]

  Ed25519Public* = array[32, byte]
  Ed25519Private* = array[64, byte]

proc crypto_kx_client_session_keys(rx: ptr byte,
                                   tx: ptr byte,
                                   client_pk: ptr byte,
                                   client_sk: ptr byte,
                                   server_pk: ptr byte): cint {.importc.}

proc crypto_kx_server_session_keys(rx: ptr byte,
                                   tx: ptr byte,
                                   client_pk: ptr byte,
                                   client_sk: ptr byte,
                                   server_pk: ptr byte): cint {.importc.}

proc crypto_sign_verify_detached(sig: ptr byte; m: ptr byte; mlen: uint64;
                                 pk: ptr byte): cint {.importc.}
proc crypto_sign_detached(sig: ptr byte; siglen_p: ptr uint64; m: ptr byte;
                          mlen: uint64; sk: ptr byte): cint {.importc.}

proc crypto_kx_keypair(pk: ptr byte, sk: ptr byte): cint {.importc.}
proc crypto_sign_ed25519_keypair(pk: ptr byte, sk: ptr byte): cint {.importc.}

proc crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: ptr byte;
    ed25519_pk: ptr byte): cint {.importc.}
proc crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: ptr byte;
    ed25519_sk: ptr byte): cint {.importc.}

proc getPublic*(priv: C25519Private): C25519Public =
  priv[32..<64].toArray(32)

proc edToC25519*(pub: Ed25519Public): C25519Public =
  var pub = pub
  doAssert 0 == crypto_sign_ed25519_pk_to_curve25519(addr result[0], addr pub[0])

proc edToC25519*(priv: Ed25519Private): C25519Private =
  var priv = priv
  doAssert 0 == crypto_sign_ed25519_sk_to_curve25519(addr result[0], addr priv[0])
  doAssert 0 == crypto_sign_ed25519_pk_to_curve25519(addr result[32], addr priv[32])

proc c25519Generate*(): C25519Private =
  doAssert 0 == crypto_kx_keypair(addr result[32], addr result[0])

proc ed25519Generate*(): Ed25519Private =
  doAssert 0 == crypto_sign_ed25519_keypair(addr result[32], addr result[0])

const c25519SignatureLength = 64

proc ed25519Sign*(data: Buffer, purpose: string, key: Ed25519Private): Buffer =
  let phash = sha256(purpose)
  var pdata = phash.toBinaryString & data.copyAsString
  let signature = newBuffer(c25519SignatureLength)
  var sigLength: uint64
  var key = key
  doAssert 0 == crypto_sign_detached(addr signature[0], addr sigLength, cast[ptr byte](addr pdata[0]), pdata.len.uint64, addr key[0])
  doAssert sigLength == c25519SignatureLength
  let target = newBuffer(c25519SignatureLength + data.len)
  target.copyFrom(signature)
  target.slice(c25519SignatureLength).copyFrom(data)
  return target

proc ed25519Unsign*(data: Buffer, purpose: string, key: Ed25519Public): Option[Buffer] =
  if data.len <= c25519SignatureLength:
    return none(Buffer)
  let phash = sha256(purpose)
  var key = key
  var pdata = phash.toBinaryString & data.slice(c25519SignatureLength).copyAsString
  let ok = crypto_sign_verify_detached(addr data[0], cast[ptr byte](addr pdata[0]), pdata.len.uint64, addr key[0])
  if ok != 0:
    return none(Buffer)

  return some(data.slice(c25519SignatureLength))

proc dhKeyExchange*(priv: C25519Private, pub: C25519Public): tuple[rx: array[32, byte], tx: array[32, byte]] =
  var res: cint
  var myPub = priv.getPublic
  var pub = pub
  var priv = priv
  if myPub.toBinaryString < pub.toBinaryString:
    res = crypto_kx_client_session_keys(addr result.rx[0], addr result.tx[0],
                                        addr myPub[0], addr priv[0],
                                        addr pub[0])
  else:
    res = crypto_kx_server_session_keys(addr result.rx[0], addr result.tx[0],
                                        addr myPub[0], addr priv[0],
                                        addr pub[0])

  doAssert res == 0

when isMainModule:
  let key = ed25519Generate()
  let signed = ed25519Sign(newView("hello"), "foo", key)
  echo signed
  let unsigned = ed25519Unsign(signed, "foo", key.getPublic)
  doAssert unsigned.get.copyAsString == "hello"
