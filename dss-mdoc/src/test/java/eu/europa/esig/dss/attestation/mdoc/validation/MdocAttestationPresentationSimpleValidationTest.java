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

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
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
import java.security.interfaces.ECPublicKey;
import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.fail;

class MdocAttestationPresentationSimpleValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    private static DSSDocument originalDocument;

    private String signer;

    @Override
    protected DSSDocument getSignedDocument() {
        CBORMap mobileSecurityObject = new CBORMap();
        mobileSecurityObject.put("version", "1.0");
        mobileSecurityObject.put("digestAlgorithm", DigestAlgorithm.SHA256.getMSOId());
        CBORMap valueDigests = new CBORMap();
        valueDigests.put("org.iso.18013.5.1", getDigestIDs(1L, DSSUtils.digest(DigestAlgorithm.SHA256, "Hello World".getBytes())));
        mobileSecurityObject.put("valueDigests", valueDigests);
        mobileSecurityObject.put("deviceKeyInfo", getDeviceKeyInfo());
        mobileSecurityObject.put("docType", "org.iso.18013.5.1.mDL");

        Calendar calendar = Calendar.getInstance();

        CBORMap validityInfo = new CBORMap();
        long signed = calendar.getTime().getTime();
        validityInfo.put("signed", signed);
        validityInfo.put("validFrom", signed);
        calendar.add(Calendar.HOUR, 1);
        validityInfo.put("validUntil", calendar.getTime().getTime());

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
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
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

    private CBORObject getDigestIDs(Long id, byte[] digest) {
        CBORMap digestId = new CBORMap();
        digestId.put(id, new CBORByteString(digest));
        return digestId;
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
