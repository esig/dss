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
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
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

class MdocAttestationPresentationWithDisclosuresDiffIdValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    private static SecureRandom secureRandom = new SecureRandom();

    private static DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {
        CBORValue.CBORMapEditor issuerNameSpaces = CBOR.map();

        CBORValue issuerSignedItems = CBOR.array()
                .add(getIssuerSignedItemBytes(1L, "family_name", "Doe"))
                .add(getIssuerSignedItemBytes(2L, "given_name", "John"))
                .add(getIssuerSignedItemBytes(4L, "birth_date",
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

        CBORValue deviceAuth = CBOR.map()
                .put("deviceMac", CBOR.array().value())
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
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertNotNull(attestationWrapper);

        List<XmlDigestMatcher> digestMatchers = attestationWrapper.getDigestMatchers();
        assertEquals(4, digestMatchers.size());

        int foundDisclosuresCounter = 0;
        int notPresentDisclosuresCounter = 0;
        int orphanDisclosuresCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            if (DigestMatcherType.SELECTIVE_DISCLOSURE == xmlDigestMatcher.getType()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                if (xmlDigestMatcher.isDataIntact()) {
                    ++foundDisclosuresCounter;
                } else {
                    ++notPresentDisclosuresCounter;
                }
            } else if (DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == xmlDigestMatcher.getType()) {
                assertFalse(xmlDigestMatcher.isDataFound());
                assertFalse(xmlDigestMatcher.isDataIntact());
                ++orphanDisclosuresCounter;
            }
        }
        assertEquals(2, foundDisclosuresCounter);
        assertEquals(1, notPresentDisclosuresCounter);
        assertEquals(1, orphanDisclosuresCounter);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        List<String> attestationIdList = simpleReport.getAttestationIdList();
        assertEquals(1, attestationIdList.size());

        assertEquals(Indication.FAILED, simpleReport.getIndication(attestationIdList.get(0)));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(attestationIdList.get(0)));
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