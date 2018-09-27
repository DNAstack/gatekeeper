package com.dnastack.gatekeeper;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.KeyPair;
import java.util.Base64;

/**
 * Utility class that generates a random keypair each time it is run. The output resembles YAML, so you can
 * probably pipe it into {@code kubectl create-secret --from-file}.
 */
public class KeyGenerator {
    public static void main(String[] args) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.forName("ES384");
        KeyPair keyPair = Keys.keyPairFor(algorithm);

        System.out.println("algorithm: " + algorithm);
        System.out.println("private: " + new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())));
        System.out.println("public: " + new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
    }
}
