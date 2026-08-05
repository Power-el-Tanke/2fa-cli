module Main (main) where

import Crypt.HOTP
import Crypt.SHA1
import Crypt.TOTP
import Data.ByteString qualified as BS
import Data.Time.Clock.System
import Data.Word
import Test.Hspec
import Test.QuickCheck

main :: IO ()
main = hspec $ do
  describe "SHA-1: hexPair" $ do
    it "splitting 0b01001100" $ hexPair (toEnum 0b01001100) `shouldBe` map toEnum [0b00000100, 0b00001100]
    it "splitting 0b00000000" $ hexPair (toEnum 0b00000000) `shouldBe` map toEnum [0b00000000, 0b00000000]
    it "splitting 0b11111111" $ hexPair (toEnum 0b11111111) `shouldBe` map toEnum [0b00001111, 0b00001111]
  describe "SHA-1: toWord8List" $ do
    it "splitting the max Word32 number" $ toWord8List (maxBound :: Word32) `shouldBe` replicate 4 (maxBound :: Word8)
    it "splitting the min word32 number" $ toWord8List (minBound :: Word32) `shouldBe` replicate 4 (minBound :: Word8)
    it "splitting 0xFF03A15A " $ toWord8List 0xFF03A15B `shouldBe` map toEnum [0xFF, 0x03, 0xA1, 0x5B]
  describe "SHA-1: fromWord8List" $ it "fromWord8List is the reverse of toWord8List" $ do
    quickCheck (\x -> x == fromWord8List (toWord8List x))
  describe "SHA-1: cut" $ do
    it "cutting lists with size == 1" $ cut 1 [1, 2, 3, 4] `shouldBe` [[1], [2], [3], [4]]
    it "cutting lists with size == 2" $ cut 2 [1, 1, 2, 2, 3, 3, 4, 4] `shouldBe` [[1, 1], [2, 2], [3, 3], [4, 4]]
    it "cutting lists with size == 4" $ cut 4 [1 .. 12] `shouldBe` [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]]
  describe "SHA-1: padding" $ do
    it "RFC example" $ do
      padding (map toEnum [0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101]) 5 `shouldBe` Left (concatMap (toWord8List . toEnum) [0x61626364, 0x65800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000028], [])
    it "65 bytes block" $ do
      chunks (BS.pack [61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61]) `shouldBe` [[61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61], [61, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 8]]
  describe "SHA-1: diggest" $ do
    it "RFC example " $ do
      msgDiggest [[0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28]] `shouldBe` [[0x61626364, 0x65800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000028]]
  describe "HOTP: fromInt64: " $ do
    it "1" $ do
      fromInt64 1 `shouldBe` [0, 0, 0, 0, 0, 0, 0, 1]
  describe "SHA-1: encoding different messages: " $ do
    it "hello world" $ do
      toString (sha1Encoding $ fromString "hello world") `shouldBe` "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    it "The quick brown fox jumps over the lazy dog" $ do
      toString (sha1Encoding $ fromString "The quick brown fox jumps over the lazy dog") `shouldBe` "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    it "The quick brown fox jumps over the lazy cog" $ do
      toString (sha1Encoding $ fromString "The quick brown fox jumps over the lazy cog") `shouldBe` "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
    it "empty message" $ do
      toString (sha1Encoding $ fromString "") `shouldBe` "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    it "GeeksForGeeks" $ do
      toString (sha1Encoding $ fromString "GeeksForGeeks") `shouldBe` "addf120b430021c36c232c99ef8d926aea2acd6b"
    it "Linux" $ do
      toString (sha1Encoding $ fromString "Linux") `shouldBe` "83ad8510bbd3f22363d068e1c96f82fd0fcccd31"
    it "Linux in 2 rounds" $ do
      toString (sha1Encoding $ sha1Encoding $ fromString "Linux") `shouldBe` "9780504402d0ff100f804fc9d1844e92165d8253"
    it "12345678901234567890" $ do
      toString (sha1Encoding $ fromString "12345678901234567890") `shouldBe` "7e0a1242bd8ef9044f27dca45f5f72ad5a1125bf"
  describe "HOTP: trunc" $ do
    it "rfc example of truncation" $ do
      trunc (BS.pack [0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a]) 6 `shouldBe` 872921
  describe "HMAC: hmacSha1" $ do
    it "c == 1" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 1)) `shouldBe` "75a48a19d4cbe100644e8ac1397eea747a2d33ab"
    it "c == 2" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 2)) `shouldBe` "0bacb7fa082fef30782211938bc1c5e70416ff44"
    it "c == 3" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 3)) `shouldBe` "66c28227d03a2d5529262ff016a1e6ef76557ece"
    it "c == 4" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 4)) `shouldBe` "a904c900a64b35909874b33e61c5938a8e15ed1c"
    it "c == 5" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 5)) `shouldBe` "a37e783d7b7233c083d4f62926c7a25f238d0316"
    it "c == 6" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 6)) `shouldBe` "bc9cd28561042c83f219324d3c607256c03272ae"
    it "c == 7" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 7)) `shouldBe` "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"
    it "c == 8" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 8)) `shouldBe` "1b3c89f65e6c9e883012052823443f048b4332db"
    it "c == 9" $ do
      (toString $ hmacSha1 (fromString "12345678901234567890") (BS.pack $ fromInt64 9)) `shouldBe` "1637409809a679dc698207310c8c7fc07290d9e5"
    it "key" $ do
      toString (hmacSha1 (fromString "key") (fromString "The quick brown fox jumps over the lazy dog")) `shouldBe` "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
  describe "HOTP" $ do
    it "second 0" $ do
      hotp (fromString "12345678901234567890") 0 6 `shouldBe` 755224
  describe "TOTP: with 8 digits" $ do
    it "1970-01-01 00:00:59" $ do
      totp 30 8 (fromString "12345678901234567890") (MkSystemTime 59 0) `shouldBe` 94287082
    it "2005-03-18 01:58:29" $ do
      totp 30 8 (fromString "12345678901234567890") (MkSystemTime 1111111109 0) `shouldBe` 07081804
    it "2005-03-18 01:58:31" $ do
      totp 30 8 (fromString "12345678901234567890") (MkSystemTime 1111111111 0) `shouldBe` 14050471
    it "2009-02-13 23:31:30" $ do
      totp 30 8 (fromString "12345678901234567890") (MkSystemTime 1234567890 0) `shouldBe` 89005924
    it "2033-05-18 03:33:20" $ do
      totp 30 8 (fromString "12345678901234567890") (MkSystemTime 2000000000 0) `shouldBe` 69279037
