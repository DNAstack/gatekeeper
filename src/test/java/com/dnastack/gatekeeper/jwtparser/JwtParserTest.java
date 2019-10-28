package com.dnastack.gatekeeper.jwtparser;

import com.dnastack.gatekeeper.config.RsaKeyHelper;
import io.jsonwebtoken.*;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;

public class JwtParserTest {
    static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRvdt2Mrt1ZjX4KCSdFH\n" +
            "NMEuENtrZzXv8Tkd0q572PGPHPx3xnkj5qNA8BZzWsb1s+MTtyW7WGuQ0V9iipBj\n" +
            "utA6X8wyGoNIEZtkWM2Xp61YMq3nNetHoW4GR7S7ILirMVO0coBHrRnsKFKMKf3Z\n" +
            "jL0s8xuy1EsTMmYBb3jdMqZxOpGgyQB4t2rUfYbHkspDQqEK6qWxNkHsX8YbQucx\n" +
            "qhu2ud2QWPczG3t11jdMWSF//yApyfOUn7X9fkhMxGMDQrvZ7W3BKOKZ6jYcm3vM\n" +
            "40X5kGJHax0ZU2KeaVAl8qrJSE7cOiv6TxnIcBJ00isVdLggzz72xK5R9R1e9MEO\n" +
            "DQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    /**
     * Check that the library we use will validate teh algorithm based on our configured key.
     */
    @Test(expected = JwtException.class)
    public void failOnWrongHeader() {
        final RSAPublicKey publicKey = RsaKeyHelper.parsePublicKey(PUBLIC_KEY);
        final Key publicKeyAsHmac = new SecretKeySpec(publicKey.getEncoded(), "HmacSHA256");
        final String tokenWithWrongAlgorithm;
        try {
            tokenWithWrongAlgorithm = Jwts.builder()
                                          .signWith(publicKeyAsHmac)
                                          .claim("foo", "bar")
                                          .compact();
        } catch (JwtException ex) {
            // Make test fail if we can't build the invalid token
            throw new AssertionError(ex);
        }

        Jwts.parser()
            .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {
                    return publicKey;
                }
            })
            .parse(tokenWithWrongAlgorithm);
    }
}
