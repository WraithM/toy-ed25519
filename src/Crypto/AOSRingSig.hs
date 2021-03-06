{-# LANGUAGE OverloadedStrings #-}

module Crypto.AOSRingSig where

import           Control.Monad   (replicateM)
import           Crypto.Hash     (Digest, SHA256, hash)
import           Data.ByteArray  (convert)
import           Data.ByteString (ByteString)

import           Crypto.Ed25519
import           Crypto.Multisig


-- AOS Ring Signatures: https://www.iacr.org/cryptodb/archive/2002/ASIACRYPT/50/50.pdf
-- Also: https://cryptoservices.github.io/cryptography/2017/07/21/Sigs.html

data RingSignature = RingSignature
    { e0 :: Integer
    , ss :: [Integer]
    } deriving (Show, Eq)


sign :: PrivateKey -> [PublicKey] -> Message -> IO RingSignature
sign prvKey pubKeys m
    | publicKey prvKey `elem` pubKeys
    = sign' m prvKey . zip pubKeys <$> replicateM (length pubKeys) randInt
    | otherwise = error "Can't sign without key in pubkey set"
  where
    randInt = (`mod` l) <$> randomInteger b


sign' :: Message -> PrivateKey -> [(PublicKey, Integer)] -> RingSignature
sign' m prvKey pubKeys = RingSignature e0 ss
  where
    n = length pubKeys
    pubKey = publicKey prvKey

    keyFirst f k = take n . dropWhile ((/= k) . f) . cycle

    (_, a):restKeys = keyFirst fst pubKey pubKeys
    ejp1 = h m $ a .* pG

    ejs = scanl eip1 (pubKey, ejp1) restKeys
    eip1 (_, ei) (pki, si) = (pki, h m $ si .* pG <> ei .* publicKeyPoint pki)

    keyjm1 = fst $ last restKeys
    ej = snd $ last ejs
    sj = (a - ej * privateKeyKey prvKey) `mod` l

    lastKey = fst $ last pubKeys
    e0 = snd . head $ keyFirst fst lastKey $ (keyjm1, ej):ejs

    firstKey = fst $ head pubKeys
    ss = map snd $ keyFirst fst firstKey $ (pubKey, sj):restKeys


verify :: [PublicKey] -> Message -> RingSignature -> Bool
verify pubKeys m (RingSignature e0 ss) = e0 == e0'
  where
    n = length pubKeys
    eip1 ei (pk, si) = h m $ si .* pG <> ei .* publicKeyPoint pk
    es = scanl eip1 e0 (zip pubKeys ss)
    e0' = es !! n


sha256Int :: ByteString -> Integer
sha256Int = fromBytes . convert . (hash :: ByteString -> Digest SHA256)


h :: Message -> Point -> Integer
h m p = sha256Int $ encodePoint p <> m
