package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3946ModifiedSigAnnotationTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-alter-signature.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        boolean firstSignatureFound = false;
        boolean secondSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
            assertNotNull(pdfRevision);

            if ("AliceSig".equals(signatureWrapper.getFirstFieldName())) {
                assertTrue(pdfRevision.isPdfSignatureDictionaryConsistent());
                checkByteRange(pdfRevision);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                // we expect to find 66 0 R added in /Annots and /Fields arrays
                assertEquals(2, Utils.collectionSize(signatureWrapper.getPdfSignatureOrFormFillChanges()));
                assertEquals(2, signatureWrapper.getPdfSignatureOrFormFillChanges().stream()
                        .filter(m -> m.getValue().contains("66 0 R")).count());
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));

                firstSignatureFound = true;

            } else if ("BobSig".equals(signatureWrapper.getFirstFieldName())) {
                assertFalse(pdfRevision.isPdfSignatureDictionaryConsistent());
                checkByteRange(pdfRevision);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                // avoid /Rect to be processed twice
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfSignatureOrFormFillChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertEquals(3, Utils.collectionSize(signatureWrapper.getPdfUndefinedChanges()));
                assertEquals(1, signatureWrapper.getPdfUndefinedChanges().stream()
                        .filter(m -> m.getValue().contains("/Rect")).count());

                secondSignatureFound = true;
            }
        }
        assertTrue(firstSignatureFound);
        assertTrue(secondSignatureFound);
    }

}
