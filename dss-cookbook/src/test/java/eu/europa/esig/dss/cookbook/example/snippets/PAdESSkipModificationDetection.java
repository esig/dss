package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESSkipModificationDetection {

    public void demo() {

        // Initialize PDF document to be validated with skipped visual comparison
        DSSDocument signedDocument = new FileDocument("src/test/resources/snippets/25sigs.pdf");

        // tag::demo[]
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
        // import eu.europa.esig.dss.pdf.IPdfObjFactory;
        // import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
        // import eu.europa.esig.dss.validation.CommonCertificateVerifier;

        // Initialize validator
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // Create a IPdfObjFactory
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        // Configure DefaultPdfDifferencesFinder responsible for visual document comparison
        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        // NOTE: To skip the visual comparison '0' value should be ser
        pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0);
        pdfObjFactory.setPdfDifferencesFinder(pdfDifferencesFinder);

        // Configure DefaultPdfObjectModificationsFinder responsible for object comparison between PDF revisions
        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        // NOTE: To skip the visual comparison '0' value should be ser
        pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(0);
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

        // Set the factory to the DocumentValidator
        validator.setPdfObjFactory(pdfObjFactory);
        // end::demo[]

        // Validate document
        Reports reports = validator.validateDocument();

    }
}
