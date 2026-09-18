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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESServiceTest extends PKIFactoryAccess {

    private static DSSDocument documentToSign;
    private static CertificateVerifier certificateVerifier;
    private static CBAdESService service;

    @BeforeEach
    void init() {
        documentToSign = new InMemoryDocument("Hello World!".getBytes());
        certificateVerifier = getCompleteCertificateVerifier();
        service = new CBAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Test
    void signatureTest() throws Exception {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate((DSSDocument) null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignaturePackaging shall be defined!", exception.getMessage());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(true);

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        signatureParameters.setGenerateTBSWithoutCertificate(false);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        certificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only CBAdES form is allowed !", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("For ECDSA with SHA512 a key with P-521 curve shall be used for a COSE! See RFC 9053.", exception.getMessage());

        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signAndValidate(documentToSign, signatureParameters);

        BLevelParameters bLevel = signatureParameters.bLevel();
        exception = assertThrows(NullPointerException.class, () -> bLevel.setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setArchiveTimestampParameters(new CBAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setContentTimestampParameters(new CBAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setSignatureTimestampParameters(new CBAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setSigningCertificateDigestMethod(null));
        assertEquals("SigningCertificateDigestMethod cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

    @Test
    void multipleDocumentsSignatureTest() throws Exception {
        DSSDocument documentToSign1 = new InMemoryDocument("Hello World!".getBytes());
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World.".getBytes());

        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class,
                () -> signAndValidate((List<DSSDocument>) null, signatureParameters));
        assertEquals("toSignDocuments cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        final List<DSSDocument> documents = Arrays.asList(documentToSign1, documentToSign2);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("SignaturePackaging shall be defined!", exception.getMessage());

        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("Not supported operation (only DETACHED are allowed for multiple document signing)!", exception.getMessage());

        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("For ECDSA with SHA512 a key with P-521 curve shall be used for a COSE! See RFC 9053.", exception.getMessage());

        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("The SigDMechanism is not defined for a detached signature! " +
                "Please use CBAdESSignatureParameters.setSigDMechanism(sigDMechanism) method.", exception.getMessage());

        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("The signed document must have names for a detached CB-AdES signature!", exception.getMessage());

        documentToSign1.setName("doc");
        documentToSign2.setName("doc");
        final List<DSSDocument> docsWithName = Arrays.asList(documentToSign1, documentToSign2);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(docsWithName, signatureParameters));
        assertEquals("The documents to be signed shall have different names! The name 'doc' appears multiple times.", exception.getMessage());

        documentToSign2.setName("anotherDoc");
        DSSDocument signedDocument = signAndValidate(docsWithName, signatureParameters);
        assertNotNull(signedDocument);
    }

    @Test
    void extensionTest() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);

        CBAdESSignatureParameters extensionParameters = new CBAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->  extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only CBAdES form is allowed !", exception.getMessage());

        extensionParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'CB-AdES-BASELINE-B' for extension.", exception.getMessage());

        extensionParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
    }

    private void extendAndValidate(DSSDocument documentToExtend, CBAdESSignatureParameters signatureParameters) {
        DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
    }

    @Test
    void createAndValidateCoseSignTest() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign.class, coseSignStructure);
        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign((COSESign) coseSignStructure);
        assertEquals(1, cborSignatures.size());
        CBORSignature cborSignature = cborSignatures.get(0);
        cborSignature.setKey(getSigningCert().getPublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void createAndValidateCoseSign1Test() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign1.class, coseSignStructure);
        COSESign1 coseSign1 = (COSESign1) coseSignStructure;
        assertTrue(coseSign1.isTagged());
        CBORSignature cborSignature = CBORSignature.fromCOSESign1(coseSign1);
        cborSignature.setKey(getSigningCert().getPublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void parallelCoseSignTest() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign.class, coseSignStructure);
        COSESign coseSign = (COSESign) coseSignStructure;
        assertTrue(coseSign.isTagged());

        awaitOneSecond();

        signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);

        DSSDocument doubleSignedDocument = sign(Collections.singletonList(signedDocument), signatureParameters);

        coseSignStructure = COSEParser.fromDocument(doubleSignedDocument).parse();
        assertInstanceOf(COSESign.class, coseSignStructure);
        coseSign = (COSESign) coseSignStructure;
        assertTrue(coseSign.isTagged());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(2, cborSignatures.size());

        for (CBORSignature cborSignature : cborSignatures) {
            cborSignature.setKey(getSigningCert().getPublicKey());
            assertTrue(cborSignature.verifySignature());
        }
    }

    @Test
    void externallySuppliedDataCoseSign1Test() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        DSSDocument externalDocument = new InMemoryDocument("Bye World!".getBytes());
        signatureParameters.setExternallySuppliedData(externalDocument);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign1.class, coseSignStructure);

        CBORSignature cborSignature = CBORSignature.fromCOSESign1((COSESign1) coseSignStructure);
        cborSignature.setKey(getSigningCert().getPublicKey());
        assertFalse(cborSignature.verifySignature());

        cborSignature.setExternalAttributesBytes(DSSUtils.toByteArray(externalDocument));
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void detachedCoseSign1Test() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                sign(Collections.singletonList(documentToSign), signatureParameters));
        assertEquals("The SigDMechanism is not defined for a detached signature! " +
                "Please use CBAdESSignatureParameters.setSigDMechanism(sigDMechanism) method.", exception.getMessage());

        signatureParameters.setSigDMechanism(SigDMechanism.NO_SIG_D);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign1.class, coseSignStructure);

        CBORSignature cborSignature = CBORSignature.fromCOSESign1((COSESign1) coseSignStructure);
        cborSignature.setKey(getSigningCert().getPublicKey());
        assertFalse(cborSignature.verifySignature());

        cborSignature.setPayloadBytes(DSSUtils.toByteArray(documentToSign));
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void untaggedCoseSign1Test() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(false);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign1.class, coseSignStructure);
        COSESign1 coseSign1 = (COSESign1) coseSignStructure;
        assertFalse(coseSign1.isTagged());
        CBORSignature cborSignature = CBORSignature.fromCOSESign1(coseSign1);
        cborSignature.setKey(getSigningCert().getPublicKey());
        assertTrue(cborSignature.verifySignature());
    }

    @Test
    void untaggedParallelCoseSignTest() {
        CBAdESSignatureParameters signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);
        signatureParameters.setTagged(false);

        DSSDocument signedDocument = sign(Collections.singletonList(documentToSign), signatureParameters);

        COSESignStructure coseSignStructure = COSEParser.fromDocument(signedDocument).parse();
        assertInstanceOf(COSESign.class, coseSignStructure);
        COSESign coseSign = (COSESign) coseSignStructure;
        assertFalse(coseSign.isTagged());

        awaitOneSecond();

        signatureParameters = initParameters();
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);
        signatureParameters.setTagged(true); // should be ignored

        DSSDocument doubleSignedDocument = sign(Collections.singletonList(signedDocument), signatureParameters);

        coseSignStructure = COSEParser.fromDocument(doubleSignedDocument).parse();
        assertInstanceOf(COSESign.class, coseSignStructure);
        coseSign = (COSESign) coseSignStructure;
        assertFalse(coseSign.isTagged());

        List<CBORSignature> cborSignatures = CBORSignature.fromCOSESign(coseSign);
        assertEquals(2, cborSignatures.size());

        for (CBORSignature cborSignature : cborSignatures) {
            cborSignature.setKey(getSigningCert().getPublicKey());
            assertTrue(cborSignature.verifySignature());
        }
    }

    private CBAdESSignatureParameters initParameters() {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    private DSSDocument signAndValidate(DSSDocument documentToSign, CBAdESSignatureParameters signatureParameters) {
        DSSDocument signedDocument = sign(documentToSign, signatureParameters);
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
    }

    private DSSDocument signAndValidate(List<DSSDocument> documentsToSign, CBAdESSignatureParameters signatureParameters) {
        DSSDocument signedDocument = sign(documentsToSign, signatureParameters);
        assertNotNull(signedDocument);
        validate(signedDocument, documentsToSign);
        return signedDocument;
    }

    private DSSDocument sign(DSSDocument documentToSign, CBAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    private DSSDocument sign(List<DSSDocument> documentsToSign, CBAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentsToSign, signatureParameters, signatureValue);
    }

    private void validate(DSSDocument documentToValidate) {
        validate(documentToValidate, null);
    }

    private void validate(DSSDocument documentToValidate, List<DSSDocument> detachedContents) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        validator.setDetachedContents(detachedContents);
        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestamp : timestampList) {
            assertTrue(timestamp.isSignatureValid());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
        }
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
