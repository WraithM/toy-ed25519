{-# LANGUAGE OverloadedStrings #-}

import           Data.Monoid     ((<>))

import           Crypto.Ed25519
import           Crypto.Multisig


testMultiSig :: IO ()
testMultiSig = do
    sk1 <- newPrivateKey
    sk2 <- newPrivateKey

    let pk1 = publicKey sk1
        pk2 = publicKey sk2
        pks = [pk1, pk2]

        evilPubKey = PublicKey $ publicKeyPoint pk2 <> inverse (publicKeyPoint pk1)
        pks' = [pk1, evilPubKey]

    (k1, r1) <- generateNoncePair
    (k2, r2) <- generateNoncePair

    let pR = combineNonces [r1, r2]

        msg = "kek"

        sig1 = signMultisig sk1 k1 pR pks msg
        sig2 = signMultisig sk2 k2 pR pks msg
        sig = combineMultisig pR [sig1, sig2]

    putStrLn . unlines $ map show
        [ verifyMultisig pks msg sig
        , verifyMultisig pks' msg sig
        ]


main :: IO ()
main = testMultiSig
