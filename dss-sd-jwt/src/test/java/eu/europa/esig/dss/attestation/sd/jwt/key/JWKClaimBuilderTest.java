/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.attestation.sd.jwt.key;

import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaim;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JWKClaimBuilderTest {

    private static CertificateToken goodUserCert;
    private static CertificateToken goodCaCert;

    @BeforeAll
    static void init() {
        goodUserCert = DSSUtils.loadCertificateFromBase64EncodedString("MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMzE4MDkzMTU3WhcNMjEwMTE4MDkzMTU3WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMtKFy1gwi9R5Ai79lTIVm6Fzjze5+ir1ejBCSNTyHy1eomoTVwD+s+ZsjsdvFseKMLY9e2Cxhck3owRHqKihOhJ7JpxK3dCTCohTUHNHIqDbozLZr/zsQOst8xSEKLyKwhWyJImLcBbm017r0p8omsUojjbCmO9nFp+KE+qoWaW6WsYsXsGzICkLjRjHP1esmd5zcYzBSId9l2wr28XFGW8qBgJKXQxeUgI190MuA6AwCld5BrLXVuLvLLzXQJ27EUfnvMIBsUSu7rAxqHKrlrqeOx+vhdrPATNWX+ifGnFsJMxToQuFfF9deMO62IzrcRSi47B+BARD+kfSiuvcaECAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFLfj6J8hqF1pc5HuOqX5HORQQUQ5MA0GCSqGSIb3DQEBCwUAA4IBAQAxDzKz7YQdW/izFnRMfUgAS7cREg9F/z7lhmCT95gn7J4TGtwE1vXpPVKjGhrPPBNFfHXQ1MXMMFPwxvO1FyHUZkfVVH6+apPGyGTHoZdIlsXfJwQDxCSBCjw7Zekbc/7ljL7fPA6kbBsXdjGk6PvKSIN9YMcCuTg/fyYPoBWKGgo76V+hiQ/SVsbOzd0SHZJazg8zYFBnAS5QpB4ccGqmhrbCoL6kIMDrWTzRYCIBPpKXN5JwwxY99kDGyUVklSt91i8Q+ioI6A9C+KrwE+gbKPxyy9HmXq4lw8rod0HFG79YOpL3zbNnXFI0Hfs5+7j4EQB4Rms3fhvnKHAsYPk8");
        goodCaCert = DSSUtils.loadCertificateFromBase64EncodedString("MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwMzE4MDkzMTU1WhcNMjEwMTE4MDkzMTU1WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfUvDNM8lvv9P5pILP98HhhM0iiGMdw/MjJOqSKdA3Ss0xXT0UeYlr0blGBFt4yKHxfIAwR8BqLviT1CA0a6+PS8EDEC29txIRCPO+BscKlz4ZFlU9g2dGwA4Dl5ynEq0AP/TYjKl5RY+rGZT/Qx8Ea5OAr9MgQWWKuONFyo7dv4tM7FMTcHUL+hUqdQEpKXXsCOT5WYjtr3oYeu34Cal8m8YN/UmK70fGDwlRHLKgDIvcfZT3dkNOehabuez2Sj6kFkWNseQWeXSjzM1f2OH9idW9UmSQ7RvxDIAgKBYD/D9gGannG2SPZWQo+w5O9UhcE1N8Nc89CLCdJguVNF9hAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgEGMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQU4tC4xPvJxRJqFXnjSqGn5Rzj5jYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFJbVMStk22yRI6dczyzj6zyIh2noFa7STDW3oWg5UdXrjvWpCrw3OSqbF1UEF6X6FtDJfrXhmgyhVwVgHzH1n6+SXG3I/lOeAOKiCNjUA7uhenZuOgoVmWdfs+c9lIx8q7/f8L/kEePoDMLOYqhsSwfDhjELuq+2OOkMOqstuRyKPLQbK7nvf985W7qdjoggm4BHNm+RxkRkrLn1DxYqxnU+2ByZbZEWsqlPTgfRobBLbgPT7PMwVdwuZ6MzdVUsmBj82kGL2duAnzE117cTLmiEluUVXy/RskcHDcbhtOyOBzmQCKmXzafSiHTHtTUPC2XgpRwfwqad4jB+iMSL9A==");
    }

    @Test
    void createMinimalECJWK() {
        PublicKeyInfo.ECKey keyInfo = PublicKeyInfo.ecKey(
                EllipticCurve.P_256,
                new byte[]{ 1, 2, 3 },
                new byte[]{ 4, 5, 6 });

        SDJWTClaim claim = new JWKClaimBuilder()
                .publicKeyInfo(keyInfo)
                .create();

        SDJWTClaimObject object = assertInstanceOf(SDJWTClaimObject.class, claim);
        assertEquals("EC", getClaim(object, "kty").getValue());
        assertEquals("P-256", getClaim(object, "crv").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getX()), getClaim(object, "x").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getY()), getClaim(object, "y").getValue());
    }

    @Test
    void createMinimalEd25519JWK() {
        PublicKeyInfo.OKPKey keyInfo = PublicKeyInfo.okpKey(
                EllipticCurve.ED25519,
                new byte[] { 10, 20, 30 });

        SDJWTClaim claim = new JWKClaimBuilder()
                .publicKeyInfo(keyInfo)
                .create();

        SDJWTClaimObject object = assertInstanceOf(SDJWTClaimObject.class, claim);

        assertEquals("OKP", getClaim(object, "kty").getValue());
        assertEquals("Ed25519", getClaim(object, "crv").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getX()), getClaim(object, "x").getValue());
    }

    @Test
    void createMinimalX25519JWK() {
        PublicKeyInfo.OKPKey keyInfo = PublicKeyInfo.okpKey(
                EllipticCurve.X25519,
                new byte[] { 10, 20, 30 });

        SDJWTClaim claim = new JWKClaimBuilder()
                .publicKeyInfo(keyInfo)
                .create();

        SDJWTClaimObject object = assertInstanceOf(SDJWTClaimObject.class, claim);

        assertEquals("OKP", getClaim(object, "kty").getValue());
        assertEquals("X25519", getClaim(object, "crv").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getX()), getClaim(object, "x").getValue());
    }

    @Test
    void createMinimalRSAJWK() {
        PublicKeyInfo.RSAKey keyInfo = PublicKeyInfo.rsaKey(
                new byte[] { 1, 2, 3, 4 },
                new byte[] { 1, 0, 1 });

        SDJWTClaim claim = new JWKClaimBuilder()
                .publicKeyInfo(keyInfo)
                .create();

        SDJWTClaimObject object = assertInstanceOf(SDJWTClaimObject.class, claim);

        assertEquals("RSA", getClaim(object, "kty").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getModulus()), getClaim(object, "n").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getExponent()), getClaim(object, "e").getValue());
    }

    @Test
    void unsupportedPublicKeyInfo() {
        PublicKeyInfo unsupported = new PublicKeyInfo() {
            @Override
            public String getKeyType() {
                return "UNKNOWN";
            }
        };

        UnsupportedOperationException exception =
                assertThrows(
                        UnsupportedOperationException.class,
                        () -> new JWKClaimBuilder()
                                .publicKeyInfo(unsupported)
                                .create());

        assertEquals("Unsupported key info type: ''", exception.getMessage());
    }

    @Test
    void includeX5TS256() {
        Digest digest = new Digest(DigestAlgorithm.SHA256, goodUserCert.getDigest(DigestAlgorithm.SHA256));

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .keyType("RSA")
                        .certificateThumbprint(digest)
                        .create());

        assertEquals("RSA", getClaim(object, "kty").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(digest.getValue()), getClaim(object, "x5t#S256").getValue());
    }

    @Test
    void unsupportedThumbprintAlgorithm() {
        Digest digest = new Digest(
                DigestAlgorithm.SHA512,
                new byte[] { 1, 2, 3 });

        UnsupportedOperationException exception =
                assertThrows(
                        UnsupportedOperationException.class,
                        () -> new JWKClaimBuilder()
                                .keyType("RSA")
                                .certificateThumbprint(digest)
                                .create());

        assertEquals("Only SHA256 is supported for a device key representation within 'jwk' claim! " +
                "Found algorithm : SHA512", exception.getMessage());
    }

    @Test
    void includeX5U() {
        String x5u = "https://example.com/certificate.pem";

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder().keyType("RSA").x5u(x5u).create());

        assertEquals("RSA", getClaim(object, "kty").getValue());
        assertEquals(x5u, getClaim(object, "x5u").getValue());
    }

    @Test
    void includeX5TS256AndX5U() {
        Digest digest = new Digest(DigestAlgorithm.SHA256, goodUserCert.getDigest(DigestAlgorithm.SHA256));
        String x5u = "https://example.com/certificate.pem";

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .keyType("RSA")
                        .certificateThumbprint(digest)
                        .x5u(x5u)
                        .create());

        assertEquals("RSA", getClaim(object, "kty").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(digest.getValue()), getClaim(object, "x5t#S256").getValue());
        assertEquals(x5u, getClaim(object, "x5u").getValue());
    }

    @Test
    void missingKeyTypeWhenNoPublicKeyInfo() {
        Digest digest = new Digest(
                DigestAlgorithm.SHA256,
                goodUserCert.getDigest(DigestAlgorithm.SHA256));

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .certificateThumbprint(digest)
                        .create());

        assertEquals(DSSJsonUtils.toBase64Url(digest.getValue()), getClaim(object, "x5t#S256").getValue());
    }

    @Test
    void includeCertificateChain() {
        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .keyType("RSA")
                        .certificateChain(Collections.singletonList(goodUserCert))
                        .create());

        assertEquals("RSA", getClaim(object, "kty").getValue());
        SDJWTClaim x5c = getClaim(object, "x5c");
        assertNotNull(x5c);
        assertNotNull(x5c.getValue());
        List<?> certList = assertInstanceOf(List.class, x5c.getValue());
        assertEquals(1, certList.size());

        SDJWTClaim certClaim = assertInstanceOf(SDJWTClaim.class, certList.get(0));
        assertEquals(DSSJsonUtils.toBase64Url(goodUserCert.getEncoded()), certClaim.getValue());
    }

    @Test
    void keyAndCertificateChain() {
        PublicKeyInfo.RSAKey keyInfo = PublicKeyInfo.rsaKey(
                new byte[]{1},
                new byte[]{1});

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder().publicKeyInfo(keyInfo)
                        .certificateChain(Arrays.asList(goodUserCert, goodCaCert))
                        .create());

        assertEquals("RSA", getClaim(object, "kty").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getModulus()), getClaim(object, "n").getValue());
        assertEquals(DSSJsonUtils.toBase64Url(keyInfo.getExponent()), getClaim(object, "e").getValue());

        SDJWTClaim x5c = getClaim(object, "x5c");
        assertNotNull(x5c);
        assertNotNull(x5c.getValue());
        List<?> certList = assertInstanceOf(List.class, x5c.getValue());
        assertEquals(2, certList.size());
        assertArrayEquals(goodUserCert.getEncoded(), Utils.fromBase64((String) ((SDJWTClaim) certList.get(0)).getValue()));
        assertArrayEquals(goodCaCert.getEncoded(), Utils.fromBase64((String) ((SDJWTClaim) certList.get(1)).getValue()));
    }

    @Test
    void keyAndEmptyCertificateChain() {
        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .publicKeyInfo(
                                PublicKeyInfo.rsaKey(
                                        new byte[] { 1 },
                                        new byte[] { 1 }))
                        .certificateChain(Collections.emptyList())
                        .create());

        assertNull(getClaim(object, "x5c"));
    }

    @Test
    void certificateChainAndThumbprint() {
        Digest digest = new Digest(
                DigestAlgorithm.SHA256,
                goodUserCert.getDigest(DigestAlgorithm.SHA256));

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .keyType("RSA")
                        .certificateChain(Collections.singletonList(goodUserCert))
                        .certificateThumbprint(digest)
                        .create());

        SDJWTClaim x5c = getClaim(object, "x5c");
        assertNotNull(x5c);
        assertNotNull(x5c.getValue());
        List<?> certList = assertInstanceOf(List.class, x5c.getValue());
        assertEquals(1, certList.size());
        assertEquals(DSSJsonUtils.toBase64Url(digest.getValue()), getClaim(object, "x5t#S256").getValue());
    }

    @Test
    void certificateChainAndX5U() {
        String x5u = "https://example.com/cert.pem";

        SDJWTClaimObject object = assertInstanceOf(
                SDJWTClaimObject.class,
                new JWKClaimBuilder()
                        .keyType("RSA")
                        .certificateChain(Collections.singletonList(goodUserCert))
                        .x5u(x5u)
                        .create());


        assertEquals("RSA", getClaim(object, "kty").getValue());

        SDJWTClaim x5c = getClaim(object, "x5c");
        assertNotNull(x5c);
        assertNotNull(x5c.getValue());
        List<?> certList = assertInstanceOf(List.class, x5c.getValue());
        assertEquals(1, certList.size());

        assertEquals(x5u, getClaim(object, "x5u").getValue());
    }

    @Test
    void keyTypeOnly() {
        JWKClaimBuilder builder = new JWKClaimBuilder().keyType("RSA");
        Exception exception = assertThrows(NullPointerException.class, builder::create);
        assertEquals("No configuration has been present for the attestation subject public key or certificate representation!", exception.getMessage());
    }

    @Test
    void noConfiguration() {
        Exception exception = assertThrows(
                NullPointerException.class,
                () -> new JWKClaimBuilder().create());

        assertEquals("No configuration has been present for the attestation subject public key or certificate representation!",
                exception.getMessage());
    }

    private SDJWTClaim getClaim(SDJWTClaimObject object, String name) {
        return object.getChildren().stream()
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElse(null);
    }

}
