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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.ByteArrayOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SDJWTCompactWithDuplicatedDisclosuresValidationTest extends AbstractSDJWTTestValidation {

    private static DSSDocument originalDocument;
    private static DSSDocument disclosuresDocument;

    static {
        String payload = "{\n" +
                "  \"_sd\": [\n" +
                "    \"CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI\",\n" +
                "    \"JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE\",\n" +
                "    \"PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI\",\n" +
                "    \"TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo\",\n" +
                "    \"XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM\",\n" +
                "    \"XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE\",\n" +
                "    \"gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM\",\n" +
                "    \"jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4\"\n" +
                "  ],\n" +
                "  \"iss\": \"https://issuer.example.com\",\n" +
                "  \"iat\": 1683000000,\n" +
                "  \"exp\": 1883000000,\n" +
                "  \"sub\": \"user_42\",\n" +
                "  \"nationalities\": [\n" +
                "    {\n" +
                "      \"...\": \"pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"...\": \"7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"vct\": \"urn:eudi:eaa:1\",\n" +
                "  \"vct#integrity\": \"sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=\",\n" +
                "  \"_sd_alg\": \"sha-256\",\n" +
                "  \"cnf\": {\n" +
                "    \"jwk\": {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"x\": \"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\n" +
                "      \"y\": \"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        originalDocument = new InMemoryDocument(payload.getBytes());
        originalDocument.setMimeType(MimeTypeEnum.JSON);

        String disclosures = "~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgI" +
                "mdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZh" +
                "bWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWl" +
                "sIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhR" +
                "IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4Z" +
                "TQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngt" +
                "MDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjog" +
                "IjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFu" +
                "eXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZR" +
                "IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5" +
                "YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92T" +
                "U5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~" +
                "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiQmVuIl0~";
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
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertNotNull(attestationWrapper);

        List<XmlDigestMatcher> digestMatchers = attestationWrapper.getDigestMatchers();
        assertEquals(11, digestMatchers.size());

        int foundDisclosuresCounter = 0;
        int notPresentDisclosuresCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.EAA_DISCLOSURE, xmlDigestMatcher.getType());
            assertTrue(xmlDigestMatcher.isDataFound());
            if (xmlDigestMatcher.isDataIntact()) {
                ++foundDisclosuresCounter;
            } else {
                ++notPresentDisclosuresCounter;
            }
        }
        assertEquals(10, foundDisclosuresCounter);
        assertEquals(1, notPresentDisclosuresCounter);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        List<String> eaaIdList = simpleReport.getEAAIdList();
        assertEquals(1, eaaIdList.size());

        assertEquals(Indication.FAILED, simpleReport.getIndication(eaaIdList.get(0)));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(eaaIdList.get(0)));
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
