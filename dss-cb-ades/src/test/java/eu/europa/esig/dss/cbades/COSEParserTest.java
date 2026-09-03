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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORTag;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Examples provided from {@link https://github.com/cose-wg/Examples}
class COSEParserTest {

    @Test
    void signEcdsaTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d8628440a054546869732069732074686520636f6e74656e7" +
                "42e818343a10126a1044231315840e2aeafd40d69d19dfe6e" +
                "52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45a" +
                "c98b8544c908b4507de1e90b717c3d34816fe926a2b98f53af" +
                "d2fa0f30a"));

        assertTrue(COSEParser.isSupported(document));

        COSEParser coseParser = COSEParser.fromDocument(document);
        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign.class, coseSignItem);
        COSESign coseSign = (COSESign) coseSignItem;
        assertNotNull(coseSign.getProtectedHeader());
        assertNotNull(coseSign.getUnprotectedHeader());
        assertNotNull(coseSign.getPayload());

        List<COSESignature> signatures = coseSign.getSignatures();
        assertEquals(1, signatures.size());
        COSESignature coseSignature = signatures.get(0);
        assertNotNull(coseSignature);
        assertNotNull(coseSignature.getProtectedHeader());
        assertNotNull(coseSignature.getUnprotectedHeader());
        assertNotNull(coseSignature.getSignature());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(1, cborSignatures.size());

        CBORSignature cborSignature = cborSignatures.get(0);
        cborSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void sign1EcdsaTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d28445a201260300a1044231315454686973206973207468" +
                "6520636f6e74656e742e58406520bbaf2081d7e0ed0f95f7" +
                "6eb0733d667005f7467cec4b87b9381a6ba1ede8e00df29f" +
                "32a37230f39a842a54821fdd223092819d7728efb9d3a008" +
                "0b75380b"));

        assertTrue(COSEParser.isSupported(document));

        COSEParser coseParser = COSEParser.fromDocument(document);
        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign1.class, coseSignItem);
        COSESign1 coseSign1 = (COSESign1) coseSignItem;
        assertNotNull(coseSign1.getProtectedHeader());
        assertNotNull(coseSign1.getUnprotectedHeader());
        assertNotNull(coseSign1.getPayload());
        assertNotNull(coseSign1.getSignature());

        CBORSignature cborSignature = CBORSignature.fromCOSESign1(coseSign1);
        cborSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void signMultipleSignaturesEcdsaTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d8628440a054546869732069732074686520636f6e74656e7" +
                "42e828343a10126a1044231315840e2aeafd40d69d19dfe6e" +
                "52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45a" +
                "c98b8544c908b4507de1e90b717c3d34816fe926a2b98f53a" +
                "fd2fa0f30a8344a1013823a104581e62696c626f2e6261676" +
                "7696e7340686f626269746f6e2e6578616d706c65588400a2" +
                "d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb629" +
                "74c863f0b160dd2163734034e6ac003b01e8705524c5c4ca4" +
                "79a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc57" +
                "71aa143966e5a469a09f613488030c5b07ec6d722e3835adb" +
                "5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f8" +
                "3ab87bb4f7a0297"));

        COSEParser coseParser = COSEParser.fromDocument(document);
        assertTrue(COSEParser.isSupported(document));

        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign.class, coseSignItem);
        COSESign coseSign = (COSESign) coseSignItem;
        assertNotNull(coseSign.getProtectedHeader());
        assertNotNull(coseSign.getUnprotectedHeader());
        assertNotNull(coseSign.getPayload());

        List<COSESignature> signatures = coseSign.getSignatures();
        assertEquals(2, signatures.size());
        for (COSESignature coseSignature : signatures) {
            assertNotNull(coseSignature);
            assertNotNull(coseSignature.getProtectedHeader());
            assertNotNull(coseSignature.getUnprotectedHeader());
            assertNotNull(coseSignature.getSignature());
        }

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(2, cborSignatures.size());

        CBORSignature cborSignatureOne = cborSignatures.get(0);

        cborSignatureOne.setKey(getECDSA256PublicKey());
        assertTrue(cborSignatureOne.verifySignature());
        cborSignatureOne.setKey(getECDSA521PublicKey());
        assertFalse(cborSignatureOne.verifySignature());

        CBORSignature cborSignatureTwo = cborSignatures.get(1);

        cborSignatureTwo.setKey(getECDSA256PublicKey());
        assertFalse(cborSignatureTwo.verifySignature());
        cborSignatureTwo.setKey(getECDSA521PublicKey());
        assertTrue(cborSignatureTwo.verifySignature());
    }

    @Test
    void signEcdsaWithCounterSigTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d8628440a1078343a10126a10442313158405ac05e289d5d0" +
                "e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d" +
                "4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887" +
                "e8802bb6650cceb2c54546869732069732074686520636f6e" +
                "74656e742e818343a10126a1044231315840e2aeafd40d69d" +
                "19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d9" +
                "82ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2" +
                "b98f53afd2fa0f30a"));

        COSEParser coseParser = COSEParser.fromDocument(document);
        assertTrue(COSEParser.isSupported(document));

        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign.class, coseSignItem);
        COSESign coseSign = (COSESign) coseSignItem;
        assertNotNull(coseSign.getProtectedHeader());
        assertNotNull(coseSign.getUnprotectedHeader());
        assertNotNull(coseSign.getPayload());

        List<COSESignature> signatures = coseSign.getSignatures();
        assertEquals(1, signatures.size());
        COSESignature coseSignature = signatures.get(0);
        assertNotNull(coseSignature);
        assertNotNull(coseSignature.getProtectedHeader());
        assertNotNull(coseSignature.getUnprotectedHeader());
        assertNotNull(coseSignature.getSignature());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(1, cborSignatures.size());

        CBORSignature cborSignature = cborSignatures.get(0);
        cborSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborSignature.verifySignature());

        COSEUnprotectedHeader unprotectedHeader = coseSign.getUnprotectedHeader();
        assertFalse(unprotectedHeader.isEmpty());

        CBORObject countersign = unprotectedHeader.getHeader(COSEHeaderParameter.COUNTER_SIGNATURE.cbor());
        assertNotNull(countersign);

        COSECounterSignStructure coseCounterSign = COSECounterSignatureParser.fromCBORObject(countersign)
                .setContext(COSESignatureType.COSE_COUNTER_SIGNATURE)
                .setMasterSignature(coseSign).parse();
        assertNotNull(coseCounterSign);

        assertInstanceOf(COSECounterSignature.class, coseCounterSign);
        COSECounterSignature coseCounterSignature = (COSECounterSignature) coseCounterSign;

        CBORSignature cborCounterSignature = CBORSignature.fromCOSECounterSignature(coseCounterSignature);
        cborCounterSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborCounterSignature.verifySignature());
    }

    @Test
    void signEcdsaWithCounterSigned1Test() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d28445a201260300a2044231310b8344a1013823a104581e6" +
                "2696c626f2e62616767696e7340686f626269746f6e2e6578" +
                "616d706c65588401b1291b0e60a79c459a4a9184a0d393e03" +
                "4b34af069a1cca34f5a913affff698002295fa9f8fcbfb6fd" +
                "ff59132fc0c406e98754a98f1fbfe81c03095f481856bc470" +
                "170227206fa5bee3c0431c56a66824e7aaf692985952e3127" +
                "1434b2ba2e47a335c658b5e995aeb5d63cf2d0ced367d3e4c" +
                "c8fffd53b70d115baa9e86961fbd1a5cf5454686973206973" +
                "2074686520636f6e74656e742e5840bb587d6b15f47bfd54d" +
                "2cbfcecef75451e92b08a514bd439fa3aa65c6ac92df0d732" +
                "8c4a47529b32add3dd1b4e940071c021e9a8f2641f1d8e3b0" +
                "53ddd65ae52"));

        COSEParser coseParser = COSEParser.fromDocument(document);
        assertTrue(COSEParser.isSupported(document));

        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign1.class, coseSignItem);
        COSESign1 coseSign1 = (COSESign1) coseSignItem;
        assertNotNull(coseSign1.getProtectedHeader());
        assertNotNull(coseSign1.getUnprotectedHeader());
        assertNotNull(coseSign1.getPayload());
        assertNotNull(coseSign1.getSignature());

        CBORSignature cborSignature = CBORSignature.fromCOSESign1(coseSign1);
        assertNotNull(cborSignature);

        cborSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborSignature.verifySignature());

        COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();
        assertFalse(unprotectedHeader.isEmpty());

        CBORObject countersignatureV2 = unprotectedHeader.getHeader(COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor());
        assertNotNull(countersignatureV2);

        COSECounterSignStructure coseCounterSign = COSECounterSignatureParser.fromCBORObject(countersignatureV2)
                .setContext(COSESignatureType.COSE_COUNTER_SIGNATURE_V2)
                .setMasterSignature(coseSign1).parse();
        assertNotNull(coseCounterSign);

        assertInstanceOf(COSECounterSignature.class, coseCounterSign);
        COSECounterSignature coseCounterSignature = (COSECounterSignature) coseCounterSign;

        CBORSignature cborCounterSignature = CBORSignature.fromCOSECounterSignature(coseCounterSignature);
        cborCounterSignature.setKey(getECDSA521PublicKey());
        assertTrue(cborCounterSignature.verifySignature());
    }

    @Test
    void signEcdsaWithCritTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d8628456a2687265736572766564f40281687265736572766" +
                "564a054546869732069732074686520636f6e74656e742e81" +
                "8343a10126a10442313158403fc54702aa56e1b2cb2028429" +
                "4c9106a63f91bac658d69351210a031d8fc7c5ff3e4be3944" +
                "5b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad" +
                "1bd9c"));

        COSEParser coseParser = COSEParser.fromDocument(document);
        assertTrue(COSEParser.isSupported(document));

        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign.class, coseSignItem);
        COSESign coseSign = (COSESign) coseSignItem;
        assertNotNull(coseSign.getProtectedHeader());
        assertNotNull(coseSign.getUnprotectedHeader());
        assertNotNull(coseSign.getPayload());

        List<COSESignature> signatures = coseSign.getSignatures();
        assertEquals(1, signatures.size());
        COSESignature coseSignature = signatures.get(0);
        assertNotNull(coseSignature);
        assertNotNull(coseSignature.getProtectedHeader());
        assertNotNull(coseSignature.getUnprotectedHeader());
        assertNotNull(coseSignature.getSignature());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(1, cborSignatures.size());

        CBORSignature cborSignature = cborSignatures.get(0);
        cborSignature.setKey(getECDSA256PublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void signRsaPssTest() throws Exception {
        DSSDocument document = new InMemoryDocument(Utils.fromHex(
                "d8628443a10300a054546869732069732074686520636f6e7" +
                "4656e742e818344a1013824a104581f6d65726961646f632e" +
                "6272616e64796275636b407273612e6578616d706c6559010" +
                "03ad4027074989995f25e167f99c9b4096fdc5c242d438d30" +
                "382ae7b30f83c88d5b5ebecb64d2256d58d3cce5c47d343bf" +
                "a532b117c2d04df3fb20679a99cf3555a7dae6098bd123b0f" +
                "3441a1e50e897cbaa1b17ce171ebab20ae2e10f16d6ee918d" +
                "37af102175979be65ebcedeb47519346ea3ed6d13b5741bc6" +
                "3742ae31342b10b46fe93f39b55fdd6e32128fd8b476fed88" +
                "f671f304d0943d2c7a33bce48df08e1f890cf5acda3ef46da" +
                "21981c3a687cfff85eeb276a98612f38d6ee63644859d66a9" +
                "ad49939ea290f7a9fdfed9af1246930f522cb8c6909567dcb" +
                "e2729716cb18a31e6f231db3d69a7a432aa3d6fa1def9c965" +
                "9616beb626f158378e0fbdd"));

        COSEParser coseParser = COSEParser.fromDocument(document);
        assertTrue(COSEParser.isSupported(document));

        COSESignStructure coseSignItem = coseParser.parse();
        assertNotNull(coseSignItem);
        assertInstanceOf(COSESign.class, coseSignItem);
        COSESign coseSign = (COSESign) coseSignItem;
        assertNotNull(coseSign.getProtectedHeader());
        assertNotNull(coseSign.getUnprotectedHeader());
        assertNotNull(coseSign.getPayload());

        List<COSESignature> signatures = coseSign.getSignatures();
        assertEquals(1, signatures.size());
        COSESignature coseSignature = signatures.get(0);
        assertNotNull(coseSignature);
        assertNotNull(coseSignature.getProtectedHeader());
        assertNotNull(coseSignature.getUnprotectedHeader());
        assertNotNull(coseSignature.getSignature());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(1, cborSignatures.size());

        CBORSignature cborSignature = cborSignatures.get(0);
        cborSignature.setKey(getRSAPSSPublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    private PublicKey getECDSA256PublicKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Base64 encoded values from the specification
        String xValue = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8";
        String yValue = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4";

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

    private PublicKey getECDSA521PublicKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Base64 encoded values from the specification
        String xValue = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
        String yValue = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1";

        // Decode the Base64 encoded x and y values
        byte[] xBytes = Utils.fromBase64(xValue);
        byte[] yBytes = Utils.fromBase64(yValue);

        // Create the EC point
        ECPoint ecPoint = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));

        // Get the named curve parameters
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp521r1");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(ecGenParameterSpec);
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

        // Create the public key specification
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

        // Generate the public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC", DSSSecurityProvider.getSecurityProvider());
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PublicKey getRSAPSSPublicKey() throws Exception {
        // Get modulus (n) and public exponent (e) from the specification
        String nValue = "BC7E29D0DF7E20CC9DC8D509E0F68895922AF0EF452190D402C61B554334A7BF91C9A570240F994FAE1B69035BCFAD" +
                "4F7E249EB26087C2665E7C958C967B1517413DC3F97A431691A5999B257CC6CD356BAD168D929B8BAE9020750E74CF60F6FD3" +
                "5D6BB3FC93FC28900478694F508B33E7C00E24F90EDF37457FC3E8EFCFD2F42306301A8205AB740515331D5C18F0C64D4A43B" +
                "E52FC440400F6BFC558A6E32884C2AF56F29E5C52780CEA7285F5C057FC0DFDA232D0ADA681B01495D9D0E32196633588E289" +
                "E59035FF664F056189F2F10FE05827B796C326E3E748FFA7C589ED273C9C43436CDDB4A6A22523EF8BCB2221615B799966F1A" +
                "BA5BC84B7A27CF";
        String eValue = "010001";

        // Decode the Base64 encoded x and y values
        byte[] nBytes = Utils.fromHex(nValue);
        byte[] eBytes = Utils.fromHex(eValue);

        // Decode hexadecimal strings to BigInteger
        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger publicExponent = new BigInteger(1, eBytes);

        // Create RSA public key specification
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);

        // Generate RSA public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    @Test
    void isCoseDocumentTest() {
        assertTrue(COSEParser.isSupported(new InMemoryDocument(new COSESign().serialize())));
        assertTrue(COSEParser.isSupported(new InMemoryDocument(new COSESign1().serialize())));

        COSESign coseSignUntagged = new COSESign();
        coseSignUntagged.setTagged(false);
        assertTrue(COSEParser.isSupported(new InMemoryDocument(coseSignUntagged.serialize())));

        COSESign1 coseSign1Untagged = new COSESign1();
        coseSign1Untagged.setTagged(false);
        assertTrue(COSEParser.isSupported(new InMemoryDocument(coseSign1Untagged.serialize())));

        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(new CBORTag(CBOR.tag(COSESignatureType.COSE_SIGN.getTag(), CBOR.nullValue()))))));
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(new CBORTag(CBOR.tag(COSESignatureType.COSE_SIGN1.getTag(), CBOR.nullValue()))))));
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(new CBORTag(CBOR.tag(COSESignatureType.COSE_COUNTER_SIGNATURE.getTag(), CBOR.nullValue()))))));
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(new CBORTag(CBOR.tag(1, CBOR.nullValue()))))));
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(new CBORArray()))));

        CBORArray cborArray = new CBORArray();
        cborArray.setTag(COSESignatureType.COSE_SIGN.getTag());
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.setTag(COSESignatureType.COSE_SIGN.getTag());
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.add(new CBORByteString());
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.add(new CBORMap());
        cborArray.add(new CBORByteString());
        cborArray.add(new CBORByteString());
        assertTrue(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.setTag(COSESignatureType.COSE_SIGN1.getTag());
        assertTrue(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.setTag(1);
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray = new CBORArray();
        cborArray.add(new CBORByteString());
        cborArray.add(new CBORMap());
        cborArray.add(new CBORByteString());
        cborArray.add(new CBORByteString());
        assertTrue(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        cborArray.add(new CBORByteString());
        assertFalse(COSEParser.isSupported(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray))));

        assertFalse(COSEParser.isSupported(new InMemoryDocument("".getBytes())));
        assertFalse(COSEParser.isSupported(new InMemoryDocument("Hello World!".getBytes())));
        assertFalse(COSEParser.isSupported(new InMemoryDocument("<?xml".getBytes())));
        assertFalse(COSEParser.isSupported(new InMemoryDocument("%PDF".getBytes())));
        assertFalse(COSEParser.isSupported(new InMemoryDocument(Utils.fromBase64("MIAGCSqGSIb3DQEH"))));
    }

}
