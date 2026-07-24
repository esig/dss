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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SDJWTCompactWithNestedDisclosuresValidationTest extends AbstractSDJWTTestValidation {

    private static DSSDocument originalDocument;
    private static DSSDocument disclosuresDocument;

    static {
        String payload = "{\n" +
                "  \"_sd\": [\n" +
                "    \"5G1srw3RG5W4pVTwSsYxeOWosRBbzd18ZoWKkC-hBL4\",\n" +
                "  ],\n" +
                "  \"iss\": \"https://issuer.example.com\",\n" +
                "  \"iat\": 1683000000,\n" +
                "  \"exp\": 1883000000,\n" +
                "  \"sub\": \"user_42\",\n" +
                "  \"_sd_alg\": \"sha-256\",\n" +
                "  \"cnf\": {\n" +
                "    \"jwk\": {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"x\": \"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\n" +
                "      \"y\": \"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"vct\": \"urn:eudi:attestation:1\",\n" +
                "  \"vct#integrity\": \"sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=\",\n" +
                "}";
        originalDocument = new InMemoryDocument(payload.getBytes());
        originalDocument.setMimeType(MimeTypeEnum.JSON);

        String disclosures = "~WyIxNl9tQWQwR2l3YVpva1UyNl8waTBoIiwiREUiXQ~WyI0ZHJmZVR" +
                "0U1VLM2FZXy1QRjEyZ2NYIiwibmF0aW9uYWxpdGllcyIsCiAgICBbCiAgICAgICAgeyAiL" +
                "i4uIjogIlBtbmxyUmpoTGN3Zjh6VERkSzE1SFZHd0h0UFlqZGR2RDM2MldqQkx3cm8iIH0" +
                "sCiAgICAgICAgeyAiLi4uIjogInI4MjNIRk42QmFfbHBTQU5ZdFhxcUNCQUgtVHNRbEl6Z" +
                "k9LMGxSQUZMQ00iIH0sCiAgICAgICAgeyAiLi4uIjogIm5QNUdZandoRm02RVNsQWVDNE5" +
                "DYUlsaVc0dHowaFRyVWVvSkIzbGI1VEEiIH0KICAgIF0KXQ~WyJmbjlmTjByRC1mRnMy" +
                "bjMwM1pJLTBjIiwiRlIiXQ~WyJZSUtlc3FPa1hYTnpNUXRzWF8tX2x3IiwiVUsiXQ~";
        disclosuresDocument = new InMemoryDocument(disclosures.getBytes());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Utils.write(DSSUtils.toByteArray(signedDocument), baos);
            Utils.write(DSSUtils.toByteArray(disclosuresDocument), baos);
            return new InMemoryDocument(baos.toByteArray(), "sd-jwt.jwt");

        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        return validator;
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        assertEquals("https://issuer.example.com", eaa.getIssuer());
        assertEquals("user_42", eaa.getSubject());
        assertEquals(DSSUtils.parseRFCDate("2029-09-01T23:33:20Z"), eaa.getExpiration());
        assertEquals(DSSUtils.parseRFCDate("2023-05-02T04:00:00Z"), eaa.getIssuedAt());
        assertEquals(Arrays.asList("DE", "FR", "UK"), eaa.getNationalities());

        List<ClaimWrapper> selectivelyDisclosableClaims = eaa.getSelectivelyDisclosableClaims();
        assertEquals(4, selectivelyDisclosableClaims.size());
        assertEquals("nationalities", selectivelyDisclosableClaims.get(0).getName());
        assertTrue(selectivelyDisclosableClaims.get(0).isSelectivelyDisclosable());
        assertEquals(3, selectivelyDisclosableClaims.get(0).getList().size());
        assertTrue(selectivelyDisclosableClaims.get(0).getList().stream().allMatch(ClaimWrapper::isSelectivelyDisclosable));
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
