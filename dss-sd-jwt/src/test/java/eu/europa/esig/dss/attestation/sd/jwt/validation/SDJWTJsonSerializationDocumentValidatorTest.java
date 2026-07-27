package eu.europa.esig.dss.attestation.sd.jwt.validation;

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

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTJsonSerializationDocumentValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument SDJWT_SIGNATURE = new FileDocument("src/test/resources/validation/sdjwt-json-valid-presentation.json");

    @Test
    void test() {
        SDJWTJsonSerializationDocumentValidator validator = new SDJWTJsonSerializationDocumentValidator();

        DSSDocument sdjwt = SDJWT_SIGNATURE;
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("{}".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("{\"payload\":\"AAA\",\"signatures\":[{\"protected\":\"BBB\",\"signature\":\"CCCC\"}]}".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("{\"payload\":\"AAA\",\"protected\":\"BBB\",\"signature\":\"CCCC\"}".getBytes());
        assertTrue(validator.isSupported(sdjwt));
        sdjwt = new InMemoryDocument("{\"hello\":\"world\"}".getBytes());
        assertTrue(validator.isSupported(sdjwt));

        DSSDocument wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~c2xzaGE~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~eyJhbGciOiJIUzI1NiJ9.c2xzaGE.c2xzaGE".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("{".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("{hello:\"world\"}".getBytes());
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
        return new SDJWTJsonSerializationDocumentValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new SDJWTJsonSerializationDocumentValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        List<DSSDocument> documents = new ArrayList<>();
        documents.add(SDJWT_SIGNATURE);
        documents.add(new FileDocument("src/test/resources/validation/sdjwt-flattened-json-valid-presentation.json"));
        return documents;
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new FileDocument("src/test/resources/validation/sdjwt-json-malformed.json");
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/sdjwt-invalid-file.json");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        return new FileDocument("src/test/resources/validation/sdjwt-json-no-signatures.json");
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
        assertEquals(containsSignature, simpleReport.getFirstAttestationId() != null);
    }

}
