-- | Implementation of https://eprint.iacr.org/2003/067.pdf

module Crypto.RingSignature where

import           Control.Monad   (replicateM)
import           Data.ByteArray  (pack, unpack)
import           Data.Function   (on)
import           Data.List       (sort, sortBy)
import           Data.Monoid     (Monoid, mconcat, (<>))

import           Crypto.Ed25519
import           Crypto.Multisig


data RingSignature = RingSignature
    { s   :: Integer
    , hRs :: [(Integer, Point)]
    } deriving (Show, Eq)


hrm :: Point -> Message -> Integer
hrm pR m = sha512Int $ encodePoint pR <> m


sign :: PrivateKey -> [PublicKey] -> Message -> IO RingSignature
sign prvKey pubKeys m = do
    ris <- replicateM (length pubKeys) generateNoncePair
    rs <- randomInteger 16
    let hRs' = hRs (map (unPublicNonce . snd) ris)
        pRs' = pRs rs hRs'
        hpR = pubKeyhR (publicKey prvKey) pRs'
    return $ RingSignature (s rs pRs' ris) (map sndTrd $ sortBy (compare `on` fst3) (hpR:hRs'))
  where
    fst3 (x, _, _) = x
    sndTrd (_, x, y) = (x, y)

    pubKeyhR pubKey pR = (pubKey, hrm pR m, pR)
    hRs = zipWith pubKeyhR pubKeys

    s rs pRs ris = (rs + sum (map (unNonce . fst) ris) + hrm pRs m * privateKeyKey prvKey) `mod` l
    pRs rs riAs = (rs `scalarMultiply` pG) <> inverse (mconcat $ map hrmA riAs)
      where
        hrmA (PublicKey pAi, _, pRi) = hrm pRi m `scalarMultiply` pAi


verify :: [PublicKey] -> Message -> RingSignature -> Bool
verify pubKeys m (RingSignature s hRs) =
    all hEq hRs && s `scalarMultiply` pG == mconcat (zipWith rha (sort pubKeys) hRs)
  where
    hEq (h, pR) = h == hrm pR m
    rha (PublicKey pA) (h, pR) = pR <> h `scalarMultiply` pA
