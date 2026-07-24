package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.common.validation.DefaultAttestationDocumentValidator;
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

class SDJWTCompactDocumentValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument SDJWT_SIGNATURE = new FileDocument("src/test/resources/validation/sdjwt-compact-valid-presentation.json");

    @Test
    void test() {
        SDJWTCompactAttestationDocumentValidator validator = new SDJWTCompactAttestationDocumentValidator();

        DSSDocument sdjwt = SDJWT_SIGNATURE;
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~c2xzaGE~".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~eyJhbGciOiJIUzI1NiJ9.c2xzaGE.c2xzaGE".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~c2xzaGE~eyJhbGciOiJIUzI1NiJ9.c2xzaGE.c2xzaGE".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~\n".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~\r\n".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~\n\n".getBytes());
        assertTrue(validator.isSupported(sdjwt));

        DSSDocument wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(" eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("\neyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9 .c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~ ".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~a.b.c.d.e".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~eyJhbGciOiJIUzI1NiJ9.c2xzaGE.c2xzaGE~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("<xml/>".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("%PDF-1.4".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(new byte[]{});
        assertFalse(validator.isSupported(wrong));
        wrong = InMemoryDocument.createEmptyDocument();
        assertFalse(validator.isSupported(wrong));
    }

    @Override
    protected SignedDocumentValidator initEmptyValidator() {
        return new SDJWTCompactAttestationDocumentValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new SDJWTCompactAttestationDocumentValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        return Collections.singletonList(SDJWT_SIGNATURE);
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA~".getBytes());
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/sdjwt-invalid-file.json");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        // not applicable
        return null;
    }

    @Override
    protected DSSDocument getXmlEvidenceRecordDocument() {
        // not applicable
        return null;
    }

    @Test
    @Override
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
        assertEquals(containsSignature, simpleReport.getFirstEAAId() != null);
    }

}

