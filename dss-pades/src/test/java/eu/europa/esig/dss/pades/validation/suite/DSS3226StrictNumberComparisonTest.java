package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS3226StrictNumberComparisonTest extends DSS3226Test {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        pdfObjectModificationsFinder.setLaxNumericComparison(false);
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

        PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
        validator.setPdfObjFactory(pdfObjFactory);

        return validator;
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
            assertNotNull(pdfRevision);
            assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
            checkPdfSignatureDictionary(pdfRevision);

            assertFalse(signatureWrapper.arePdfModificationsDetected());
            if (Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges())) {
                validSigFound = true;
            } else {
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

}
