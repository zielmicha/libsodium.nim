import os

type SodiumError = object of Exception

template checkzero*(err: int) =
  if err != 0:
    raise newException(SodiumError, "libsodium error")

import collections/bytes
export byteArray, toBinaryString

{.passl:"-lsodium".}
