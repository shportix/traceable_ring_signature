Project is devided on 6 parts:
-curves
-eccsecp256k1
-ed25519
-point
-signature
-signature_test

#signature
This part consists implementation of main functionality:
- function Gen_keys() generate key pair for signing 
- function Sign() signing message 
- function Verify() verifying signature
- function Link() returns signatures with same auth
- Curve is interface for all curves
- TraceRingSignature is struct for signature

#eccsecp256k1
Implementation of secp256k1 curve

#ed25519
Implementation of ed25519 curve

#point
Implementation of interface for all curves points

#curves
Library of curves

#signature_test
Implementation of tests
