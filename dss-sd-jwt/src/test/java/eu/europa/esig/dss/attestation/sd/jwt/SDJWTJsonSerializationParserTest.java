package eu.europa.esig.dss.attestation.sd.jwt;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTJsonSerializationParserTest {

    @Test
    void simpleSdJwtTest() throws Exception {
        DSSDocument sdJwtDoc = new FileDocument("src/test/resources/validation/sdjwt-flattened-json-simple.json");
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(sdJwtDoc);
        assertTrue(parser.isSupported());

        SDJWTSerializationObject sdjwtSerializationObject = parser.parse();
        assertNotNull(sdjwtSerializationObject.getSignature());
        assertEquals(1, sdjwtSerializationObject.getSignature().getSignatures().size());

        assertNull(sdjwtSerializationObject.getDisclosures());
        assertNull(sdjwtSerializationObject.getKeyBindingSignature());

        JWS jws = sdjwtSerializationObject.getSignature().getSignatures().get(0);
        jws.setKey(getECDSA256PublicKey());
        assertTrue(jws.verifySignature());

    }

    @Test
    void sdJwtWithDisclosuresTest() {
        DSSDocument sdJwtDoc = new FileDocument("src/test/resources/validation/sdjwt-flattened-json-valid-presentation.json");
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(sdJwtDoc);
        assertTrue(parser.isSupported());

        SDJWTSerializationObject sdjwtSerializationObject = parser.parse();
        assertNotNull(sdjwtSerializationObject.getSignature());
        assertEquals(1, sdjwtSerializationObject.getSignature().getSignatures().size());

        assertEquals(1, sdjwtSerializationObject.getDisclosures().size());
        assertNull(sdjwtSerializationObject.getKeyBindingSignature());
    }

    @Test
    void sdJwtPresentationTest() {
        DSSDocument sdJwtDoc = new FileDocument("src/test/resources/validation/sdjwt-json-valid-presentation.json");
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(sdJwtDoc);
        assertTrue(parser.isSupported());

        SDJWTSerializationObject sdjwtSerializationObject = parser.parse();
        assertNotNull(sdjwtSerializationObject.getSignature());
        assertEquals(1, sdjwtSerializationObject.getSignature().getSignatures().size());

        assertEquals(2, sdjwtSerializationObject.getDisclosures().size());
        assertNotNull(sdjwtSerializationObject.getKeyBindingSignature());
    }

    @Test
    void notSupportedTest() {
        DSSDocument compactDoc = new FileDocument("src/test/resources/validation/sdjwt-compact-valid-presentation.json");
        SDJWTJsonSerializationParser parser = new SDJWTJsonSerializationParser(compactDoc);
        assertFalse(parser.isSupported());

        DSSDocument invalidDoc = new FileDocument("src/test/resources/validation/sdjwt-invalid-file.json");
        parser = new SDJWTJsonSerializationParser(invalidDoc);
        assertFalse(parser.isSupported());
    }

    private PublicKey getECDSA256PublicKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Base64 encoded values from the specification
        String xValue = "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ";
        String yValue = "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8";

        // Decode the Base64 encoded x and y values
        byte[] xBytes = Utils.fromBase64(xValue);
        byte[] yBytes = Utils.fromBase64(yValue);

        // Create the EC point
        ECPoint ecPoint = new ECPoint(new java.math.BigInteger(1, xBytes), new java.math.BigInteger(1, yBytes));

        // Get the named curve parameters
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(ecGenParameterSpec);
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

        // Create the public key specification
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC", DSSSecurityProvider.getSecurityProvider());
        return keyFactory.generatePublic(publicKeySpec);
    }

}

