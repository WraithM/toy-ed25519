-- Implementation of https://eprint.iacr.org/2003/067.pdf

module Crypto.RingSignature where

import           Control.Monad         (replicateM)
import           Data.ByteArray        (pack, unpack)
import           Data.Monoid           (Monoid, mconcat, (<>))
import           System.Random.Shuffle (shuffleM)

import           Crypto.Ed25519
import           Crypto.Multisig


data RingSignature = RingSignature
    { s         :: Integer
    , pubKeyhRs :: [(PublicKey, Integer, Point)]
    } deriving (Show, Eq)


hrm :: Point -> Message -> Integer
hrm pR m = sha512Int $ encodePoint pR <> m


sign :: PrivateKey -> [PublicKey] -> Message -> IO RingSignature
sign prvKey@(PrivateKey k) pubKeys m = do
    ris <- replicateM (length pubKeys) generateNoncePair
    rs <- randomInteger
    let hRs' = hRs (map (unPublicNonce . snd) ris)
        pRs' = pRs rs hRs'
        hpR = pubKeyhR (publicKey prvKey) pRs'
    RingSignature (s rs pRs' ris) <$> shuffleM (hpR:hRs')
  where
    pubKeyhR pubKey pR = (pubKey, hrm pR m, pR)
    hRs = zipWith pubKeyhR pubKeys

    hk = unpack $ sha512 k
    lsbHashInt = fromBytes . pack $ drop b hk

    s rs pRs ris = (rs + sum (map (unNonce . fst) ris) + hrm pRs m * lsbHashInt) `mod` l
    pRs rs riAs = (rs `scalarMultiply` pB) <> inverse (mconcat $ map hrmA riAs)
      where
        hrmA (PublicKey pAi, _, pRi) = hrm pRi m `scalarMultiply` pAi


verify :: [PublicKey] -> Message -> RingSignature -> Bool
verify pubKeys m (RingSignature s hRs) = all (`elem` pubKeys) sigPubKeys && all hEq hRs &&
    s `scalarMultiply` pB == mconcat (map rha hRs)
  where
    sigPubKeys = map (\(pk, _, _) -> pk) hRs
    hEq (_, h, pR) = h == hrm pR m
    rha (PublicKey pA, h, pR) = pR <> h `scalarMultiply` pA
