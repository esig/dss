package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestEvidenceRecordValidator {

    protected abstract EvidenceRecordValidator initEmptyValidator();

    protected abstract EvidenceRecordValidator initValidator(DSSDocument document);

    protected abstract List<DSSDocument> getValidDocuments();

    protected abstract DSSDocument getMalformedDocument();

    protected abstract DSSDocument getOtherTypeDocument();

    protected DSSDocument getBinaryDocument() {
        return new InMemoryDocument(new byte[] { '1', '2', '3' });
    }

    protected abstract DSSDocument getSignatureDocument();

    @Test
    public void validateEvidenceRecords() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            EvidenceRecordValidator validator = initValidator(document);
            validate(validator, true);
        }
    }

    @Test
    public void validateFromDocumentWithSignedDocumentValidator() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
            validate(validator, true);
        }
    }

    @Test
    public void validateFromDocumentWithEvidenceRecordValidator() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
            validate(validator, true);
        }
    }

    @Test
    public void binaryDocumentValidation() {
        DSSDocument document = getBinaryDocument();
        assertThrows(IllegalInputException.class, () -> initValidator(document));
    }

    @Test
    public void malformedDocumentValidation() {
        DSSDocument document = getMalformedDocument();
        assertThrows(IllegalInputException.class, () -> initValidator(document));
    }

    @Test
    public void otherDocumentTypeValidation() {
        DSSDocument document = getOtherTypeDocument();
        assertThrows(IllegalInputException.class, () -> initValidator(document));
    }

    @Test
    public void isSupportedValidDocument() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            assertTrue(initEmptyValidator().isSupported(document));
        }
    }

    @Test
    public void isSupportedBinaryDocument() {
        assertFalse(initEmptyValidator().isSupported(getBinaryDocument()));
    }

    @Test
    public void isSupportedMalformedDocument() {
        assertFalse(initEmptyValidator().isSupported(getMalformedDocument()));
    }

    @Test
    public void isSupportedOtherTypeDocument() {
        assertFalse(initEmptyValidator().isSupported(getOtherTypeDocument()));
    }

    @Test
    public void isSupportedSignatureDocument() {
        assertFalse(initEmptyValidator().isSupported(getSignatureDocument()));
    }

    protected void validate(SignedDocumentValidator validator) {
        validate(validator, false);
    }

    protected void validate(SignedDocumentValidator validator, boolean containsEvidenceRecords) {
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);
        assertEquals(containsEvidenceRecords, Utils.isCollectionNotEmpty(simpleReport.getEvidenceRecordIdList()));
    }

}
