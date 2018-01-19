{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Crypto.Multisig where

import           Crypto.Random   (getRandomBytes)
import           Data.ByteArray  (pack, unpack)
import           Data.ByteString (ByteString)
import           Data.Monoid     (Monoid, mconcat)

import           Crypto.Ed25519


newtype Nonce = Nonce Integer deriving (Show, Eq)


newtype PublicNonce = PublicNonce { unPublicNonce :: Point } deriving (Show, Eq, Monoid)


generateNoncePair :: IO (Nonce, PublicNonce)
generateNoncePair = do
    n <- fromBytes <$> getRandomBytes 16
    return (Nonce n, PublicNonce $ n `scalarMultiply` pB)


combineNonces :: [PublicNonce] -> PublicNonce
combineNonces = mconcat


newtype PartialSignature = PartialSignature { unPartialSig :: Integer } deriving (Show, Eq)


signMultisig :: PrivateKey  -- ^ Private key for partial signature
             -> Nonce       -- ^ Private nonce
             -> PublicNonce -- ^ Sum of all public nonces
             -> PublicKey   -- ^ Sum of all public keys
             -> Message     -- ^ Message to sign
             -> PartialSignature
signMultisig (PrivateKey k) (Nonce r) (PublicNonce pR) pubKeys m = PartialSignature s
  where
    h = unpack $ sha512 k
    lsbHashInt = fromBytes . pack $ drop b h

    s = (r + hram pR pubKeys m * lsbHashInt) `mod` l


combineMultisig :: PublicNonce -> [PartialSignature] -> Signature
combineMultisig (PublicNonce pR) = Signature pR . sum . map unPartialSig


verifyMultisig :: [PublicKey] -> Message -> Signature -> Bool
verifyMultisig = verify . mconcat
