import os

type SodiumError = object of Exception

template checkzero*(err: int) =
  if err != 0:
    raise newException(SodiumError, "libsodium error")

proc byteArray*(data: string, size: static[int]): array[size, byte] =
  if data.len != size:
    raise newException(ValueError, "bad length")
  copyMem(addr result, data.cstring, size)

proc toBinaryString*[T: array](s: T): string =
  const size = s.high - s.low + 1
  result = newString(size)
  copyMem(result.cstring, unsafeAddr(s), size)

{.passl:"-lsodium".}
