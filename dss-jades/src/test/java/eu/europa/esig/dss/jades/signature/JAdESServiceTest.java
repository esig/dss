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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConverter;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESServiceTest extends PKIFactoryAccess {

    private static DSSDocument documentToSign;
    private static CertificateVerifier certificateVerifier;
    private static JAdESService service;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument("src/test/resources/sample.json");
        certificateVerifier = getCompleteCertificateVerifier();
        service = new JAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Test
    void signatureTest() throws Exception {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate((DSSDocument) null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(true);

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignaturePackaging shall be defined!", exception.getMessage());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel shall be defined!", exception.getMessage());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

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
        assertEquals("Only JAdES form is allowed !", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signAndValidate(documentToSign, signatureParameters);

        BLevelParameters bLevel = signatureParameters.bLevel();
        exception = assertThrows(NullPointerException.class, () -> bLevel.setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Only JAdES_BASELINE_B level is allowed for JAdES Compact Signature! " +
                "Change JwsSerializationType in JAdESSignatureParameters in order to support extension!", exception.getMessage());

        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setArchiveTimestampParameters(new JAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setContentTimestampParameters(new JAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setSignatureTimestampParameters(new JAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);

        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setSigningCertificateDigestMethod(null));
        assertEquals("SigningCertificateDigestMethod cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

    private DSSDocument signAndValidate(DSSDocument documentToSign, JAdESSignatureParameters signatureParameters) {
        DSSDocument signedDocument = sign(documentToSign, signatureParameters);
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
    }

    private DSSDocument sign(DSSDocument documentToSign, JAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
                getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    @Test
    void multipleDocumentsSignatureTest() throws Exception {
        DSSDocument documentToSign1 = new InMemoryDocument("Hello World!".getBytes());
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World.".getBytes());

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class,
                () -> signAndValidate((List<DSSDocument>) null, signatureParameters));
        assertEquals("toSignDocuments cannot be null!", exception.getMessage());

        final List<DSSDocument> documents = Arrays.asList(documentToSign1, documentToSign2);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("SignaturePackaging shall be defined!", exception.getMessage());

        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("Not supported operation (only DETACHED are allowed for multiple document signing)!", exception.getMessage());

        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("SignatureLevel shall be defined!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("The SigDMechanism is not defined for a detached signature! " +
                "Please use JAdESSignatureParameters.setSigDMechanism(sigDMechanism) method.", exception.getMessage());

        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
        assertEquals("The signed document must have names for a detached JAdES signature!", exception.getMessage());

        documentToSign1.setName("doc");
        documentToSign2.setName("doc");
        final List<DSSDocument> docsWithName = Arrays.asList(documentToSign1, documentToSign2);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(docsWithName, signatureParameters));
        assertEquals("The documents to be signed shall have different names! The name 'doc' appears multiple times.", exception.getMessage());

        documentToSign2.setName("anotherDoc");
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        DSSDocument signedDocument = signAndValidate(documents, signatureParameters);
        assertNotNull(signedDocument);
    }

    private DSSDocument signAndValidate(List<DSSDocument> documentsToSign, JAdESSignatureParameters signatureParameters) {
        DSSDocument signedDocument = sign(documentsToSign, signatureParameters);
        assertNotNull(signedDocument);
        validate(signedDocument, documentsToSign);
        return signedDocument;
    }

    private DSSDocument sign(List<DSSDocument> documentsToSign, JAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentsToSign, signatureParameters, signatureValue);
    }

    @Test
    void extensionTest() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);

        JAdESSignatureParameters extensionParameters = new JAdESSignatureParameters();

        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->  extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only JAdES form is allowed !", exception.getMessage());

        extensionParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("The type 'COMPACT_SERIALIZATION' does not support signature extension!", exception.getMessage());

        extensionParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'JAdES-BASELINE-B' for extension.", exception.getMessage());

        extensionParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
    }

    private void extendAndValidate(DSSDocument documentToExtend, JAdESSignatureParameters signatureParameters) {
        DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
    }

    @Test
    void addSignaturePolicyStoreTest() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        DSSDocument signaturePolicy = new InMemoryDocument("Hello world!".getBytes());
        Policy policy = new Policy();
        policy.setId("Policy Id");
        policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        policy.setDigestValue(signaturePolicy.getDigestValue(DigestAlgorithm.SHA256));
        signatureParameters.bLevel().setSignaturePolicy(policy);

        DSSDocument signedDocument = sign(documentToSign, signatureParameters);

        Exception exception = assertThrows(NullPointerException.class,
                () -> service.addSignaturePolicyStore(null, null));
        assertEquals("The document cannot be null", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> service.addSignaturePolicyStore(signedDocument, null));
        assertEquals("The signaturePolicyStore cannot be null", exception.getMessage());

        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();

        exception = assertThrows(NullPointerException.class,
                () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("SpDocSpecification must be provided", exception.getMessage());

        SpDocSpecification spDocSpecification = new SpDocSpecification();
        signaturePolicyStore.setSpDocSpecification(spDocSpecification);

        exception = assertThrows(NullPointerException.class,
                () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("ID (OID or URI) for SpDocSpecification must be provided", exception.getMessage());

        spDocSpecification.setId("Policy-Id");

        exception = assertThrows(IllegalArgumentException.class,
                () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("SignaturePolicyStore shall contain either SignaturePolicyContent document or sigPolDocLocalURI!", exception.getMessage());

        signaturePolicyStore.setSignaturePolicyContent(new InMemoryDocument("Bye world!".getBytes()));

        exception = assertThrows(IllegalInputException.class,
                () -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
        assertEquals("The extended signature shall have JSON Serialization (or Flattened) type! " +
                "Use JWSConverter to convert the signature.", exception.getMessage());

        DSSDocument convertedSignature = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(signedDocument);
        exception = assertThrows(IllegalInputException.class,
                () -> service.addSignaturePolicyStore(convertedSignature, signaturePolicyStore));
        assertEquals("The process did not find a signature to add SignaturePolicyStore!", exception.getMessage());

        signaturePolicyStore.setSignaturePolicyContent(signaturePolicy);

        DSSDocument documentWithPolicy = service.addSignaturePolicyStore(convertedSignature, signaturePolicyStore);
        assertNotNull(documentWithPolicy);

        validate(documentWithPolicy);

        signaturePolicyStore.setSigPolDocLocalURI("/local/path/policy.xml");

        exception = assertThrows(IllegalArgumentException.class,
                () -> service.addSignaturePolicyStore(convertedSignature, signaturePolicyStore));
        assertEquals("SignaturePolicyStore shall contain either SignaturePolicyContent document or sigPolDocLocalURI!", exception.getMessage());

        signaturePolicyStore.setSignaturePolicyContent(null);

        documentWithPolicy = service.addSignaturePolicyStore(convertedSignature, signaturePolicyStore);
        assertNotNull(documentWithPolicy);
    }

    private void validate(DSSDocument documentToValidate) {
        validate(documentToValidate, Collections.emptyList());
    }

    private void validate(DSSDocument documentToValidate, List<DSSDocument> detachedDocuments) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        validator.setDetachedContents(detachedDocuments);

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
        return GOOD_USER;
    }

}
