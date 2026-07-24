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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.AttestationPresentationType;
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

class MdocAttestationPresentationWithDisclosuresDiffNamespaceValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    private static SecureRandom secureRandom = new SecureRandom();

    private static DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {
        CBORMap issuerNameSpaces = new CBORMap();

        CBORArray issuerSignedItems = new CBORArray();
        issuerSignedItems.add(getIssuerSignedItemBytes(1L, "family_name", "Doe"));
        issuerSignedItems.add(getIssuerSignedItemBytes(2L, "given_name", "John"));
        issuerSignedItems.add(getIssuerSignedItemBytes(3L, "birth_date",
                DSSUtils.formatDateWithCustomFormat(DSSUtils.getUtcDate(2000, Calendar.JANUARY, 1), DSSUtils.ISO8601_DATE_FORMAT)));
        issuerNameSpaces.put("org.iso.18013.5.1", issuerSignedItems);

        CBORMap mobileSecurityObject = new CBORMap();
        mobileSecurityObject.put("version", "1.0");
        mobileSecurityObject.put("digestAlgorithm", DigestAlgorithm.SHA256.getMSOId());
        CBORMap valueDigests = new CBORMap();

        CBORMap digestIDs = new CBORMap();
        List<CBORObject> issuerSignedItemsAsList = issuerSignedItems.getValueAsList();
        for (int i = 0; i < issuerSignedItems.getSize() - 1; i++) {
            CBORByteString cborBtsr = (CBORByteString) issuerSignedItemsAsList.get(i);
            digestIDs.put((long) i + 1, DSSUtils.digest(DigestAlgorithm.SHA256, CBORUtils.serializeCborObject(cborBtsr)));
        }
        valueDigests.put("org.iso.18013.5.1", digestIDs);

        digestIDs = new CBORMap();
        for (int i = issuerSignedItems.getSize() - 1; i < issuerSignedItems.getSize(); i++) {
            CBORByteString cborBtsr = (CBORByteString) issuerSignedItemsAsList.get(i);
            digestIDs.put((long) i + 1, DSSUtils.digest(DigestAlgorithm.SHA256, CBORUtils.serializeCborObject(cborBtsr)));
        }
        valueDigests.put("org.iso.23220.1", digestIDs);

        mobileSecurityObject.put("valueDigests", valueDigests);
        mobileSecurityObject.put("deviceKeyInfo", getDeviceKeyInfo());
        mobileSecurityObject.put("docType", "org.iso.18013.5.1.mDL");

        Calendar calendar = Calendar.getInstance();

        CBORMap validityInfo = new CBORMap();
        Date signed = calendar.getTime();
        validityInfo.put("signed", toCborDateTime(signed));
        validityInfo.put("validFrom", toCborDateTime(signed));
        calendar.add(Calendar.HOUR, 1);
        validityInfo.put("validUntil", toCborDateTime(calendar.getTime()));

        mobileSecurityObject.put("validityInfo", validityInfo);

        CBORByteString mobileSecurityObjectBytes = CBORUtils.toCborBtsrWrappedTagged(mobileSecurityObject);
        originalDocument = new InMemoryDocument(CBORUtils.serializeCborObject(mobileSecurityObjectBytes));

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

        CBORMap mdocResponse = new CBORMap();
        mdocResponse.put("version", "1.0");

        CBORArray documents = new CBORArray();
        CBORMap document = new CBORMap();
        document.put("docType", "org.iso.18013.5.1.mDL");

        CBORMap issuerSigned = new CBORMap();
        issuerSigned.put("nameSpaces", issuerNameSpaces);
        issuerSigned.put("issuerAuth", toCbor(signedDocument));
        document.put("issuerSigned", issuerSigned);

        CBORMap deviceSigned = new CBORMap();
        deviceSigned.put("nameSpaces", CBORUtils.toCborBtsrWrappedTagged(new CBORMap())); // empty

        CBORMap deviceAuth = new CBORMap();
        deviceAuth.put("deviceMac", new CBORArray());
        deviceSigned.put("deviceAuth", deviceAuth);
        document.put("deviceSigned", deviceSigned);

        documents.add(document);
        mdocResponse.put("documents", documents);
        mdocResponse.put("status", 0L);

        // embed in mdoc
        DSSDocument mdocDocument = new InMemoryDocument(CBORUtils.serializeCborObject(mdocResponse));
        return mdocDocument;
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
        assertEquals(4, digestMatchers.size());

        int foundDisclosuresCounter = 0;
        int notPresentDisclosuresCounter = 0;
        int orphanDisclosuresCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            if (DigestMatcherType.EAA_DISCLOSURE == xmlDigestMatcher.getType()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                if (xmlDigestMatcher.isDataIntact()) {
                    ++foundDisclosuresCounter;
                } else {
                    ++notPresentDisclosuresCounter;
                }
            } else if (DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == xmlDigestMatcher.getType()) {
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

        List<String> eaaIdList = simpleReport.getEAAIdList();
        assertEquals(1, eaaIdList.size());

        assertEquals(Indication.FAILED, simpleReport.getIndication(eaaIdList.get(0)));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(eaaIdList.get(0)));
    }

    @Override
    protected AttestationPresentationType getEAAPresentationType() {
        return AttestationPresentationType.MDOC_DEVICE_RESPONSE;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    private CBORMap getDeviceKeyInfo() {
        signer = ECDSA_USER;

        CBORMap deviceKeyInfo = new CBORMap();
        CBORMap coseKey = new CBORMap();
        coseKey.put(1L, 2L); // 'kty' ECDSA
        coseKey.put(-1L, EllipticCurve.P_256.getCOSEValue().longValue()); // 'crv'
        coseKey.put(-2L, toBytes(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineX(), 32)); // 'x'
        coseKey.put(-3L, toBytes(((ECPublicKey) getSigningCert().getPublicKey()).getW().getAffineY(), 32)); // 'y'

        deviceKeyInfo.put("deviceKey", coseKey);
        return deviceKeyInfo;
    }

    private CBORObject toCbor(DSSDocument document) {
        try {
            return CBORUtils.parseCbor(document);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private CBORObject toCborDateTime(Date date) {
        String dateTime = DSSUtils.formatDateToRFC(date);
        CBORObject cborObject = CBORObjectFactory.toCBORObject(dateTime);
        cborObject.setTag(0L);
        return cborObject;
    }

    private CBORObject getIssuerSignedItemBytes(Long id, String elementIdentifier, Object elementValue) {
        CBORMap issuerSignedItem = new CBORMap();
        issuerSignedItem.put("digestID", id);
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        issuerSignedItem.put("random", randomBytes);
        issuerSignedItem.put("elementIdentifier", elementIdentifier);
        issuerSignedItem.put("elementValue", elementValue);
        return CBORUtils.toCborBtsrWrappedTagged(issuerSignedItem);
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