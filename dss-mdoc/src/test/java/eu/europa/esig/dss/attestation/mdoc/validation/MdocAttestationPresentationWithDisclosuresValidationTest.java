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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class MdocAttestationPresentationWithDisclosuresValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    private static SecureRandom secureRandom = new SecureRandom();

    private static DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {
        CBORValue.CBORMapEditor issuerNameSpaces = CBOR.map();

        CBORValue issuerSignedItems = CBOR.array()
                .add(getIssuerSignedItemBytes(1L, "family_name", "Doe"))
                .add(getIssuerSignedItemBytes(2L, "given_name", "John"))
                .add(getIssuerSignedItemBytes(3L, "birth_date",
                        DSSUtils.formatDateWithCustomFormat(DSSUtils.getUtcDate(
                                2000, Calendar.JANUARY, 1), DSSUtils.ISO8601_DATE_FORMAT)))
                .value();
        issuerNameSpaces.put("org.iso.18013.5.1", issuerSignedItems);

        CBORValue.CBORMapEditor digestIDs = CBOR.map();
        List<CBORValue> issuerSignedItemsAsList = issuerSignedItems.getElements();
        for (int i = 0; i < issuerSignedItems.size(); i++) {
            CBORValue cborBtsr = issuerSignedItemsAsList.get(i);
            digestIDs.put((long) i + 1, DSSUtils.digest(DigestAlgorithm.SHA256, CBORUtils.serializeCbor(cborBtsr)));
        }
        CBORValue valueDigests = CBOR.map()
                .put("org.iso.18013.5.1", digestIDs.value())
                .value();

        Calendar calendar = Calendar.getInstance();

        CBORValue.CBORMapEditor validityInfo = CBOR.map();
        Date signed = calendar.getTime();
        validityInfo.put("signed", CBORTags.tdate(signed));
        validityInfo.put("validFrom", CBORTags.tdate(signed));
        calendar.add(Calendar.HOUR, 1);
        validityInfo.put("validUntil", CBORTags.tdate(calendar.getTime()));

        CBORValue mobileSecurityObject = CBOR.map()
                .put("version", "1.0")
                .put("digestAlgorithm", DigestAlgorithm.SHA256.getMSOId())
                .put("valueDigests", valueDigests)
                .put("deviceKeyInfo", getDeviceKeyInfo())
                .put("docType", "org.iso.18013.5.1.mDL")
                .put("validityInfo", validityInfo.value())
                .value();

        CBORValue mobileSecurityObjectBytes = CBORTags.encodedCbor(mobileSecurityObject.encodeToBytes());
        originalDocument = new InMemoryDocument(CBORUtils.serializeCbor(mobileSecurityObjectBytes));

        signer = GOOD_USER;

        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(false);

        CBAdESService service = new CBAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        CBORValue.CBORMapEditor mdocResponse = CBOR.map();
        mdocResponse.put("version", "1.0");

        CBORValue.CBORMapEditor document = CBOR.map();
        document.put("docType", "org.iso.18013.5.1.mDL");

        CBORValue issuerSigned = CBOR.map()
                .put("nameSpaces", issuerNameSpaces.value())
                .put("issuerAuth", toCbor(signedDocument))
                .value();
        document.put("issuerSigned", issuerSigned);

        CBORValue deviceMac = CBOR.array()
                .add(CBOR.bytes(new byte[0]))
                .add(CBOR.map().value())
                .add(CBOR.nullValue())
                .add(CBOR.bytes(new byte[0]))
                .value();

        CBORValue deviceAuth = CBOR.map()
                .put("deviceMac", deviceMac)
                .value();

        CBORValue deviceSigned = CBOR.map()
                .put("nameSpaces", CBORTags.encodedCbor(CBOR.map().value().encodeToBytes())) // empty
                .put("deviceAuth", deviceAuth)
                .value();
        document.put("deviceSigned", deviceSigned);

        CBORValue documents = CBOR.array()
                .add(document.value())
                .value();
        mdocResponse.put("documents", documents);
        mdocResponse.put("status", 0L);

        // embed in mdoc
        DSSDocument mdocDocument = new InMemoryDocument(CBORUtils.serializeCbor(mdocResponse.value()));
        return mdocDocument;
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
        assertNotNull(attestation.getIssuedAt());
        assertNotNull(attestation.getNotBefore());
        assertNotNull(attestation.getExpiration());

        assertNotNull(attestation.getDevicePublicKey());
        assertEquals("1.0", attestation.getVersion());
        assertEquals("org.iso.18013.5.1.mDL", attestation.getAttestationDocumentType());

        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());
        assertEquals(CBORUtils.parseTDate("2000-01-01T00:00:00Z"), attestation.getBirthdate());

        List<ClaimWrapper> selectivelyDisclosableClaims = attestation.getSelectiveDisclosures();
        assertEquals(3, selectivelyDisclosableClaims.size());

        List<ClaimWrapper> payloadClaims = attestation.getAllAttestationPayloadClaims();
        assertNotNull(payloadClaims);

        boolean validityInfoClaimFound = false;
        boolean versionClaimFound = false;
        boolean docTypeClaimFound = false;
        boolean deviceKeyClaimFound = false;
        boolean givenNameClaimFound = false;
        boolean secondNameClaimFound = false;
        boolean birthdayClaimFound = false;
        for (ClaimWrapper disclosableClaim : payloadClaims) {
            if ("validityInfo".equals(disclosableClaim.getName())) {
                assertNotNull(disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                validityInfoClaimFound = true;

            } else if ("version".equals(disclosableClaim.getName())) {
                assertEquals("1.0", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                versionClaimFound = true;

            } else if ("docType".equals(disclosableClaim.getName())) {
                assertEquals("org.iso.18013.5.1.mDL", disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                docTypeClaimFound = true;

            } else if ("deviceKeyInfo".equals(disclosableClaim.getName())) {
                assertNotNull(disclosableClaim.getDisplayValue());
                assertFalse(disclosableClaim.isSelectivelyDisclosable());
                deviceKeyClaimFound = true;

            } else if ("given_name".equals(disclosableClaim.getName())) {
                assertEquals("John", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                givenNameClaimFound = true;

            } else if ("family_name".equals(disclosableClaim.getName())) {
                assertEquals("Doe", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                secondNameClaimFound = true;

            } else if ("birth_date".equals(disclosableClaim.getName())) {
                assertEquals("2000-01-01T00:00:00Z", disclosableClaim.getDisplayValue());
                assertTrue(disclosableClaim.isSelectivelyDisclosable());
                birthdayClaimFound = true;

            } else {
                fail(String.format("Not processed claim with name '%s'", disclosableClaim.getName()));
            }
        }
        assertTrue(validityInfoClaimFound);
        assertTrue(versionClaimFound);
        assertTrue(docTypeClaimFound);
        assertTrue(deviceKeyClaimFound);
        assertTrue(givenNameClaimFound);
        assertTrue(secondNameClaimFound);
        assertTrue(birthdayClaimFound);
    }

    @Override
    protected AttestationDocumentFormat getAttestationPresentationType() {
        return AttestationDocumentFormat.MDOC_DEVICE_RESPONSE;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    private CBORValue getDeviceKeyInfo() {
        signer = ECDSA_USER;

        CBORValue coseKey = CBOR.map()
                .put(1L, 2L) // 'kty' ECDSA
                .put(-1L, EllipticCurve.P_256.getCOSEValue().longValue()) // 'crv'
                .put(-2L, toBytes(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineX(), 32)) // 'x'
                .put(-3L, toBytes(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineY(), 32)) // 'y'
                .value();

        return CBOR.map()
                .put("deviceKey", coseKey)
                .value();
    }

    private CBORValue toCbor(DSSDocument document) {
        try {
            return CBORUtils.parseCbor(document);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private CBORValue getIssuerSignedItemBytes(Long id, String elementIdentifier, Object elementValue) {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);

        CBORValue issuerSignedItem = CBOR.map()
                .put("digestID", id)
                .put("random", randomBytes)
                .put("elementIdentifier", elementIdentifier)
                .put("elementValue", elementValue)
                .value();
        return CBORTags.encodedCbor(issuerSignedItem.encodeToBytes());
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
