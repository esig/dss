package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESDisableVisualComparison {

    public void demo() {

        // Initialize PDF document to be validated with skipped visual comparison
        DSSDocument signedDocument = new FileDocument("src/test/resources/snippets/25sigs.pdf");

        // Initialize validator
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);

        // Provide an instance of CertificateVerifier
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // Provide a custom instance of PdfObjFactory, that uses a PDFSignatureService with skipped visual comparison
        validator.setPdfObjFactory(getPdfObjFactory());

        // Validate document
        Reports reports = validator.validateDocument();
    }

    private IPdfObjFactory getPdfObjFactory() {
        return new MockNativePdfObjFactory();
    }

    private class MockNativePdfObjFactory extends PdfBoxNativeObjectFactory {

        @Override
        public PDFSignatureService newPAdESSignatureService() {
            PdfBoxSignatureService service = new PdfBoxSignatureService(PDFServiceMode.SIGNATURE, new PdfBoxNativeSignatureDrawerFactory());
            // Skip visual comparison
            service.setMaximalPagesAmountForVisualComparison(0);
            return service;
        }

        @Override
        public PDFSignatureService newContentTimestampService() {
            PdfBoxSignatureService service =  new PdfBoxSignatureService(PDFServiceMode.CONTENT_TIMESTAMP, new PdfBoxNativeSignatureDrawerFactory());
            // Skip visual comparison
            service.setMaximalPagesAmountForVisualComparison(0);
            return service;
        }

        @Override
        public PDFSignatureService newSignatureTimestampService() {
            PdfBoxSignatureService service =  new PdfBoxSignatureService(PDFServiceMode.SIGNATURE_TIMESTAMP, new PdfBoxNativeSignatureDrawerFactory());
            // Skip visual comparison
            service.setMaximalPagesAmountForVisualComparison(0);
            return service;
        }

        @Override
        public PDFSignatureService newArchiveTimestampService() {
            PdfBoxSignatureService service =  new PdfBoxSignatureService(PDFServiceMode.ARCHIVE_TIMESTAMP, new PdfBoxNativeSignatureDrawerFactory());
            // Skip visual comparison
            service.setMaximalPagesAmountForVisualComparison(0);
            return service;
        }

    }

}
