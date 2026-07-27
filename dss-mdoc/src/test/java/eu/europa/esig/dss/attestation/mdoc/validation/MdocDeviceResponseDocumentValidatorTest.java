package eu.europa.esig.dss.attestation.mdoc.validation;

import co.nstant.in.cbor.model.UnicodeString;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.validation.AbstractTestDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocDeviceResponseDocumentValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument MINIMAL_DEVICE_RESPONSE = buildMinimalDeviceResponse();

    private static DSSDocument buildMinimalDeviceResponse() {
        CBORMap issuerSigned = new CBORMap();
        issuerSigned.put("version", new CBORSimpleObject(new UnicodeString("1.0")));
        issuerSigned.put("status", 0);
        return new InMemoryDocument(CBORUtils.serializeCborObject(issuerSigned));
    }

    private static CBORMap buildDocument() {
        CBORMap document = new CBORMap();
        document.put("docType", "org.iso.18013.5.1.mDL");
        document.put("issuerSigned", buildIssuerSigned());
        document.put("deviceSigned", buildDeviceSigned());
        return document;
    }

    private static CBORMap buildIssuerSigned() {
        CBORMap issuerSigned = new CBORMap();
        issuerSigned.put("issuerAuth", buildCoseSign1());
        return issuerSigned;
    }

    private static CBORMap buildDeviceSigned() {
        CBORMap deviceSigned = new CBORMap();
        deviceSigned.put("nameSpaces", new CBORMap().getByteString());
        deviceSigned.put("deviceAuth", buildCoseSign1());
        return deviceSigned;
    }

    private static CBORArray buildCoseSign1() {
        CBORArray coseSign1 = new CBORArray(4);
        coseSign1.add(new CBORByteString());
        coseSign1.add(new CBORMap());
        coseSign1.add(createEmptyMSO());
        coseSign1.add(new CBORByteString());
        return coseSign1;
    }

    private static CBORByteString createEmptyMSO() {
        CBORMap msoMap = new CBORMap();
        CBORByteString msoBytes = msoMap.getByteString();
        return new CBORByteString(CBORUtils.serializeCborObject(msoBytes));
    }

    private static CBORMap buildDocumentError() {
        CBORMap document = new CBORMap();
        document.put("org.iso.23220.1.mID", 1);
        return document;
    }

    @Test
    void test() {
        MdocDeviceResponseDocumentValidator validator = new MdocDeviceResponseDocumentValidator();

        DSSDocument mdoc = MINIMAL_DEVICE_RESPONSE;
        assertTrue(validator.isSupported(mdoc));

        CBORMap allKeys = new CBORMap();
        allKeys.put("version", new CBORSimpleObject(new UnicodeString("1.0")));
        allKeys.put("documents", new CBORArray(Collections.singletonList(buildDocument())));
        allKeys.put("documentErrors", new CBORArray(Collections.singletonList(buildDocumentError())));
        allKeys.put("status", 0);
        mdoc = new InMemoryDocument(CBORUtils.serializeCborObject(allKeys));
        assertTrue(validator.isSupported(mdoc));

        mdoc = new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
        assertTrue(validator.isSupported(mdoc));

        CBORMap wrongKeyMap = new CBORMap();
        wrongKeyMap.put("test", 1);
        DSSDocument wrong = new InMemoryDocument(CBORUtils.serializeCborObject(wrongKeyMap));
        assertFalse(validator.isSupported(wrong));
        wrong = new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor");
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(CBORUtils.serializeCborObject(new CBORArray()));
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("hello".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("<xml/>".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(new byte[]{});
        assertFalse(validator.isSupported(wrong));
        wrong = InMemoryDocument.createEmptyDocument();
        assertFalse(validator.isSupported(wrong));
    }

    @Override
    protected SignedDocumentValidator initEmptyValidator() {
        return new MdocDeviceResponseDocumentValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new MdocDeviceResponseDocumentValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        return Collections.singletonList(new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc"));
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument(CBORUtils.serializeCborObject(new CBORArray()));
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        return MINIMAL_DEVICE_RESPONSE;
    }

    @Override
    protected DSSDocument getXmlEvidenceRecordDocument() {
        // not applicable
        return null;
    }

    @Override
    @Test
    public void validateFromDocument() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            DocumentValidator reader = DefaultAttestationDocumentValidator.fromDocument(document);
            validate(reader, true);
        }
    }

    @Override
    protected void validate(DocumentValidator validator, boolean containsSignature) {
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);
        assertEquals(containsSignature, simpleReport.getFirstAttestationId() != null);
    }

}
