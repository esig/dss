package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

// See DSS-3422
public class PAdESMultipleLTLevelSignaturesTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/lt-short.pdf"));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = new MockPDFDocumentValidator(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        return validator;
    }

    @Override
    protected Reports validateDocument(DocumentValidator validator) {
        Reports reports = super.validateDocument(validator);
        assertEquals(73, ((MockPDFDocumentValidator) validator).getCounter());
        return reports;
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    private static class MockPDFDocumentValidator extends PDFDocumentValidator {

        protected MockPDFDocumentValidator(DSSDocument document) {
            super(new MockPDFDocumentAnalyzer(document));
        }

        protected int getCounter() {
            return ((MockPDFDocumentAnalyzer) getDocumentAnalyzer()).getCounter();
        }

    }

    private static class MockPDFDocumentAnalyzer extends PDFDocumentAnalyzer {

        MockValidationContext svc = null;

        protected MockPDFDocumentAnalyzer(DSSDocument document) {
            super(document);
        }

        @Override
        protected ValidationContext createValidationContext() {
            svc = new MockValidationContext(getValidationTime());
            return svc;
        }

        protected int getCounter() {
            return svc.getCounter();
        }

    }

    private static class MockValidationContext extends SignatureValidationContext {

        int counter = 0;

        protected MockValidationContext(Date validationTime) {
            super(validationTime);
        }

        @Override
        public void addDocumentCertificateSource(CertificateSource certificateSource) {
            super.addDocumentCertificateSource(certificateSource);
            ++counter;
        }

        protected int getCounter() {
            return counter;
        }

    }

}
