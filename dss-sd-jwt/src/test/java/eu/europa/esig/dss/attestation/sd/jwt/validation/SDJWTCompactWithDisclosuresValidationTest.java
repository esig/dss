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

import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SDJWTCompactWithDisclosuresValidationTest extends AbstractSDJWTTestValidation {

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
                "U5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~";
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

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        assertEquals("https://issuer.example.com", attestation.getIssuer());
        assertEquals("user_42", attestation.getSubject());
        assertEquals(DSSUtils.parseRFCDate("2029-09-01T23:33:20Z"), attestation.getExpiration());
        assertEquals(DSSUtils.parseRFCDate("2023-05-02T04:00:00Z"), attestation.getIssuedAt());
        assertEquals(DSSUtils.parseRFCDate("2019-10-02T07:06:40Z"), attestation.getUpdatedAt());

        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());
        assertEquals("johndoe@example.com", attestation.getEmail());
        assertNull(attestation.getEmailVerified());
        assertEquals(DSSUtils.parseRFCDate("1940-01-01T00:00:00Z"), attestation.getBirthdate());
        assertEquals("Anytown", attestation.getAddressCity());
        assertEquals("Anystate", attestation.getAddressStateOrProvince());
        assertEquals("US", attestation.getAddressCountry());
        assertEquals("123 Main St", attestation.getStreetAddress());
        assertEquals("+1-202-555-0101", attestation.getPhoneNumber());
        assertTrue(attestation.getPhoneNumberVerified());
        assertEquals(Arrays.asList("US", "DE"), attestation.getNationalities());

        assertEquals("urn:eudi:eaa:1", attestation.getVerifiableCredentialsTypeUri());
        assertEquals(DigestAlgorithm.SHA256, attestation.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
        assertNotNull(attestation.getVerifiableCredentialsTypeIntegrityBytes());

        List<ClaimWrapper> selectivelyDisclosableClaims = attestation.getSelectivelyDisclosableClaims();
        assertEquals(10, selectivelyDisclosableClaims.size());

        List<ClaimWrapper> payloadClaims = attestation.getAllAttestationPayloadClaims();
        assertNotNull(payloadClaims);

        boolean issuerClaimFound = false;
        boolean subjectClaimFound = false;
        boolean issuedAtClaimFound = false;
        boolean expTimeClaimFound = false;
        boolean updTimeClaimFound = false;
        boolean firstNameClaimFound = false;
        boolean secondNameClaimFound = false;
        boolean birthdayClaimFound = false;
        boolean emailClaimFound = false;
        boolean addressClaimFound = false;
        boolean phoneNumberClaimFound = false;
        boolean phoneNumberVerifiedClaimFound = false;
        boolean nationalitiesClaimFound = false;
        boolean cnfClaimFound = false;
        boolean vctClaimFound = false;
        boolean vctIntegrityClaimFound = false;
        for (ClaimWrapper disclosableClaim : payloadClaims) {
            if ("iss".equals(disclosableClaim.getName())) {
                assertEquals("https://issuer.example.com", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                issuerClaimFound = true;

            } else if ("sub".equals(disclosableClaim.getName())) {
                assertEquals("user_42", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                subjectClaimFound = true;

            } else if ("iat".equals(disclosableClaim.getName())) {
                assertEquals("2023-05-02T04:00:00Z", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                issuedAtClaimFound = true;

            } else if ("exp".equals(disclosableClaim.getName())) {
                assertEquals("2029-09-01T23:33:20Z", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                expTimeClaimFound = true;

            } else if ("updated_at".equals(disclosableClaim.getName())) {
                assertEquals("2019-10-02T07:06:40Z", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                updTimeClaimFound = true;

            } else if ("given_name".equals(disclosableClaim.getName())) {
                assertEquals("John", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                firstNameClaimFound = true;

            } else if ("family_name".equals(disclosableClaim.getName())) {
                assertEquals("Doe", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                secondNameClaimFound = true;

            } else if ("email".equals(disclosableClaim.getName())) {
                assertEquals("johndoe@example.com", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                emailClaimFound = true;

            } else if ("birthdate".equals(disclosableClaim.getName())) {
                assertEquals("1940-01-01T00:00:00Z", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                birthdayClaimFound = true;

            } else if ("address".equals(disclosableClaim.getName())) {
                assertEquals(DSSJsonUtils.parseJsonString("{\"street_address\": \"123 Main St\", \"locality\": \"Anytown\", " +
                        "\"region\": \"Anystate\", \"country\": \"US\"}"), DSSJsonUtils.parseJsonString(disclosableClaim.getDisplayValue()));
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                addressClaimFound = true;

            } else if ("phone_number".equals(disclosableClaim.getName())) {
                assertEquals("+1-202-555-0101", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                phoneNumberClaimFound = true;

            } else if ("phone_number_verified".equals(disclosableClaim.getName())) {
                assertEquals("true", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                phoneNumberVerifiedClaimFound = true;

            } else if ("nationalities".equals(disclosableClaim.getName())) {
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                assertEquals(2, disclosableClaim.getList().size());
                assertTrue(disclosableClaim.getList().stream().allMatch(ClaimWrapper::isSelectivelyDisclosable));
                assertEquals("US, DE", disclosableClaim.getDisplayValue());
                nationalitiesClaimFound = true;

            } else if ("cnf".equals(disclosableClaim.getName())) {
                assertEquals(DSSJsonUtils.parseJsonString("{\"jwk\": {\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": " +
                        "\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\", \"y\": \"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}}"),
                        DSSJsonUtils.parseJsonString(disclosableClaim.getDisplayValue()));
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                cnfClaimFound = true;

            } else if ("vct".equals(disclosableClaim.getName())) {
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                assertEquals("urn:eudi:eaa:1", disclosableClaim.getText());
                vctClaimFound = true;

            } else if ("vct#integrity".equals(disclosableClaim.getName())) {
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                assertEquals("sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=", disclosableClaim.getText());
                vctIntegrityClaimFound = true;

            } else {
                fail(String.format("Not processed claim with name '%s'", disclosableClaim.getName()));
            }
        }
        assertTrue(issuerClaimFound);
        assertTrue(subjectClaimFound);
        assertTrue(issuedAtClaimFound);
        assertTrue(expTimeClaimFound);
        assertTrue(updTimeClaimFound);
        assertTrue(firstNameClaimFound);
        assertTrue(secondNameClaimFound);
        assertTrue(birthdayClaimFound);
        assertTrue(emailClaimFound);
        assertTrue(addressClaimFound);
        assertTrue(phoneNumberClaimFound);
        assertTrue(phoneNumberVerifiedClaimFound);
        assertTrue(nationalitiesClaimFound);
        assertTrue(cnfClaimFound);
        assertTrue(vctClaimFound);
        assertTrue(vctIntegrityClaimFound);
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
