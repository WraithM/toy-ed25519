{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Crypto.Ed25519 where

import           Crypto.Hash     (Digest, SHA512, hash)
import           Crypto.Random   (getRandomBytes)
import           Data.Bits       (shiftL, shiftR, (.&.), (.|.))
import           Data.ByteArray  (convert, pack, unpack)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Monoid     ((<>))


data Point = Point Integer Integer deriving (Show, Eq)


expMod :: Integer -> Integer -> Integer -> Integer
expMod _ 0 _ = 1
expMod b e m
    | odd e     = (t * b) `mod` m
    | otherwise = t
  where
    t = (expMod b (e `div` 2) m ^ 2) `mod` m


inv :: Integer -> Integer
inv x = expMod x (q - 2) q


d :: Integer
d = negate $ 121665 * inv 121666


q :: Integer
q = 2 ^ 255 - 19


l :: Integer
l = 2 ^ 252 + 27742317777372353535851937790883648493


pB :: Point
pB = Point (recoverX y `mod` q) (y `mod` q)
  where
    y = 4 * inv 5


i :: Integer
i = expMod 2 ((q - 1) `div` 4) q


recoverX :: Integer -> Integer
recoverX y
    | (x*x - xx) `mod` q /= 0 =
        if x' `mod` 2 /= 0 then q - x' else x'
    | x `mod` 2 /= 0 = q - x
    | otherwise = x
  where
    xx = (y*y - 1) * inv (d*y*y + 1)
    x = expMod xx ((q + 3) `div` 8) q
    x' = x*i `mod` q


add :: Point -> Point -> Point
add (Point x1 y1) (Point x2 y2) = Point (newX `mod` q) (newY `mod` q)
  where
    denom = d*x1*x2*y1*y2
    newX = (x1*y2 + y1*x2) * inv (1 + denom)
    newY = (y1*y2 + x1*x2) * inv (1 - denom)


identity :: Point
identity = Point 0 1


inverse :: Point -> Point
inverse (Point x y) = Point (negate x) y


instance Monoid Point where
    mempty = identity
    mappend = add


-- TODO get rid of explicit recursion
scalarMultiply :: (Monoid m, Integral a) => a -> m -> m
scalarMultiply 0 _ = mempty
scalarMultiply 1 x = x
scalarMultiply 2 x = x <> x
scalarMultiply n x
    | even n =      scalarMultiply (n `div` 2) (x <> x)
    | odd n  = x <> scalarMultiply (n `div` 2) (x <> x)


isOnCurve :: Point -> Bool
isOnCurve (Point x y) = (y*y - x*x - 1 - d*x*x*y*y) `mod` q == 0


point :: Integer -> Integer -> Maybe Point
point x y
    | isOnCurve p = Just p
    | otherwise   = Nothing
  where
    p = Point x y


newtype PrivateKey = PrivateKey { k :: ByteString } deriving (Show, Eq)


newtype PublicKey = PublicKey Point deriving (Show, Eq, Monoid)


data Signature = Signature
    { pR :: Point
    , s  :: Integer
    } deriving (Show, Eq)


privateKey :: ByteString -> Maybe PrivateKey
privateKey bs
    | BS.length bs == b = Just (PrivateKey bs)
    | otherwise         = Nothing
  where
    b = 32


newPrivateKey :: IO PrivateKey
newPrivateKey = maybe err return . privateKey =<< getRandomBytes 32
  where err = fail "Something went horribly wrong"


fromBytes :: ByteString -> Integer
fromBytes = BS.foldl' f 0
  where
    f a b = a `shiftL` 8 .|. fromIntegral b


-- TODO no explicit recursion
toBytes :: Integer -> ByteString
toBytes = BS.pack . pad . reverse . toDigits
  where
    pad xs | length xs == 32 = xs
           | otherwise = replicate (32 - length xs) 0 <> xs
    toDigits 0 = []
    toDigits n = fromIntegral (n `mod` 256) : toDigits (n `div` 256)


publicKey :: PrivateKey -> PublicKey
publicKey (PrivateKey k) = PublicKey $ lsbHashInt `scalarMultiply` pB
  where
    b = 32
    h = unpack $ sha512 k
    lsbHashInt = fromBytes . pack $ drop b h


encodePoint :: Point -> ByteString
encodePoint (Point x y) = toBytes x <> toBytes y


decodePoint :: ByteString -> Point
decodePoint = Point <$> fromBytes . BS.take 32 <*> fromBytes . BS.drop 32


encodeSignature :: Signature -> ByteString
encodeSignature (Signature r s) = encodePoint r <> toBytes s


decodeSignature :: ByteString -> Signature
decodeSignature = Signature <$> decodePoint . BS.take 64 <*> fromBytes . BS.drop 64


type Message = ByteString


hram :: Point -> PublicKey -> Message -> Integer
hram pR (PublicKey pubKey) m = fromBytes . sha512Digest $ encodePoint pR <> encodePoint pubKey <> m


sign :: PrivateKey -> Message -> Signature
sign prvKey@(PrivateKey k) m = Signature pR s
  where
    pubKey = publicKey prvKey

    h = unpack $ sha512 k
    b = 32
    lsbHashInt = fromBytes . pack $ drop b h
    msbHash = pack $ take b h

    r = fromBytes . sha512Digest $ msbHash <> m
    pR = r `scalarMultiply` pB
    s = (r + hram pR pubKey m * lsbHashInt) `mod` l


verify :: PublicKey -> Message -> Signature -> Bool
verify pubKey@(PublicKey a) m (Signature pR s) =
    s `scalarMultiply` pB == pR <> (h `scalarMultiply` a)
  where
    h = hram pR pubKey m


sha512 :: ByteString -> Digest SHA512
sha512 = hash


sha512Digest :: ByteString -> ByteString
sha512Digest = convert . sha512
