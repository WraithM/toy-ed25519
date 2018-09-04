{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Crypto.Multisig where

import           Crypto.Hash     (Digest, SHA256, hash)
import           Crypto.Random   (getRandomBytes)
import           Data.ByteArray  (convert, pack, unpack)
import           Data.ByteString (ByteString)
import           Data.List       (sort)

import           Crypto.Ed25519


newtype Nonce = Nonce { unNonce :: Integer } deriving (Show, Eq)


newtype PublicNonce = PublicNonce { unPublicNonce :: Point } deriving (Show, Eq, Semigroup, Monoid)


randomInteger :: Int -> IO Integer
randomInteger n = fromBytes <$> getRandomBytes n


generateNoncePair :: IO (Nonce, PublicNonce)
generateNoncePair = do
    n <- randomInteger 16
    return (Nonce n, PublicNonce $ n `scalarMultiply` pB)


combineNonces :: [PublicNonce] -> PublicNonce
combineNonces = mconcat


newtype PartialSignature = PartialSignature { unPartialSig :: Integer } deriving (Show, Eq)


multisigPublicKey :: [PublicKey] -> PublicKey
multisigPublicKey pubKeys = mconcat $ map delinearizePubkey pubKeys
  where
    delinearizePubkey pubKey = PublicKey $ delinearCoeff pubKeys pubKey `scalarMultiply` publicKeyPoint pubKey


signMultisig :: PrivateKey  -- ^ Private key for partial signature
             -> Nonce       -- ^ Private nonce
             -> PublicNonce -- ^ Sum of all public nonces
             -> [PublicKey] -- ^ All of the public keys
             -> Message     -- ^ Message to sign
             -> PartialSignature
signMultisig privKey@(PrivateKey k) (Nonce r) (PublicNonce pR) pubKeys m = PartialSignature s
  where
    pubKey = publicKey privKey

    h = unpack $ sha512 k
    lsbHashInt = fromBytes . pack $ drop b h

    s = (r + delinearCoeff pubKeys pubKey * hram pR (multisigPublicKey pubKeys) m * lsbHashInt) `mod` l


combineMultisig :: PublicNonce -> [PartialSignature] -> Signature
combineMultisig (PublicNonce pR) = Signature pR . sum . map unPartialSig


verifyMultisig :: [PublicKey] -> Message -> Signature -> Bool
verifyMultisig = verify . multisigPublicKey


delinearCoeff :: [PublicKey] -> PublicKey -> Integer
delinearCoeff pubKeys pubKey = h0 $ serializedPubKeys pubKeys <> encodePublicKey pubKey
  where
    serializedPubKeys = sha256Digest . mconcat . sort . map encodePublicKey
    h0 = fromBytes . sha256Digest
    sha256Digest = convert . sha256
    sha256 :: ByteString -> Digest SHA256
    sha256 = hash
