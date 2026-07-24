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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEAA;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

class SDJWTCompactWithKBBySignCertTest extends AbstractSDJWTTestValidation {

    private DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {
        signer = ECDSA_USER;

        String payload = "{\n" +
                "  \"iss\": \"https://issuer.example.com\",\n" +
                "  \"iat\": 1683000000,\n" +
                "  \"nbf\": 1683000000,\n" +
                "  \"exp\": 1883000000,\n" +
                "  \"sub\": \"user_42\",\n" +
                "  \"_sd_alg\":" + "\"" + DigestAlgorithm.SHA256.getSDJWTId() + "\",\n" +
                "  \"nationalities\": [\n" +
                "    \"US\"\n" +
                "  ],\n" +
                "  \"cnf\": {\n" +
                "    \"jwk\": {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"x\": \"" + toBase64Url(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineX(), 32) + "\",\n" +
                "      \"y\": \"" + toBase64Url(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineY(), 32) + "\",\n" +
                "      \"x5c\": [\"" + Utils.toBase64(getSigningCert().getEncoded()) + "\"]\n" +
                "    }\n" +
                "  },\n" +
                "  \"family_name\": \"Doe\",\n" +
                "  \"address\": {\n" +
                "    \"street_address\": \"123 Main St\",\n" +
                "    \"locality\": \"Anytown\",\n" +
                "    \"region\": \"Anystate\",\n" +
                "    \"country\": \"US\"\n" +
                "  },\n" +
                "  \"given_name\": \"John\",\n" +
                "  \"vct\": \"urn:eudi:attestation:1\",\n" +
                "  \"vct#integrity\": \"sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=\",\n" +
                "}";
        originalDocument = new InMemoryDocument(payload.getBytes());
        originalDocument.setMimeType(MimeTypeEnum.JSON);

        signer = GOOD_USER;

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        DSSDocument attestationPresentation;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Utils.write(DSSUtils.toByteArray(signedDocument), baos);
            baos.write('~');
            attestationPresentation = new InMemoryDocument(baos.toByteArray(), "simple-sd-jwt.jwt");

        } catch (Exception e) {
            fail(e);
            return null;
        }

        signer = ECDSA_USER;

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setIncludeCertificateChain(false);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        signatureParameters.setSignatureType("kb+jwt");

        payload = "{\n" +
                "  \"nonce\": \"1234567890\",\n" +
                "  \"aud\": \"https://verifier.example.org\",\n" +
                "  \"iat\": 1748537244,\n" +
                "  \"sd_hash\": " + "\"" + DSSJsonUtils.toBase64Url(attestationPresentation.getDigest(DigestAlgorithm.SHA256).getValue()) + "\"\n"  +
                "}";
        DSSDocument kbSignedDocument = new InMemoryDocument(payload.getBytes());
        kbSignedDocument.setMimeType(MimeTypeEnum.JSON);

        service = new JAdESService(getOfflineCertificateVerifier());
        dataToSign = service.getDataToSign(kbSignedDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument keyBindingDocument = service.signDocument(kbSignedDocument, signatureParameters, signatureValue);

        DSSDocument sdJwtKb = new InMemoryDocument(DSSJsonUtils.concatenateDSSDocuments(Arrays.asList(attestationPresentation, keyBindingDocument), false));
        return sdJwtKb;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        return validator;
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        XmlEAA eaa = simpleReport.getEAAById(simpleReport.getFirstEAAId());
        assertEquals(Indication.PASSED, eaa.getIndication());

        List<XmlSignature> signatures = eaa.getEAASignature();
        assertEquals(1, signatures.size());
        assertEquals(Indication.TOTAL_PASSED, signatures.get(0).getIndication());

        XmlSignature keyBindingSignature = eaa.getKeyBindingSignature();
        assertEquals(Indication.TOTAL_PASSED, keyBindingSignature.getIndication());
        assertNull(keyBindingSignature.getAdESValidationDetails());
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    private String toBase64Url(BigInteger bigInteger, int size) {
        return DSSJsonUtils.toBase64Url(toBytes(bigInteger, size));
    }

    private byte[] toBytes(BigInteger bigInteger, int size) {
        byte[] bytes = bigInteger.toByteArray();

        if (bytes.length == size) return bytes;

        if (bytes.length == size + 1 && bytes[0] == 0) {
            // remove leading zero
            return java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        byte[] result = new byte[size];
        System.arraycopy(bytes, 0, result, size - bytes.length, bytes.length);
        return result;
    }

}
