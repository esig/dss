package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3946ModifiedSigAnnotationTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-3946/attack_modify_stream.pdf"));
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
                assertTrue(pdfRevision.isPdfSignatureDictionaryConsistent());
                checkByteRange(pdfRevision);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                // avoid /Rect to be processed twice
                assertEquals(3, Utils.collectionSize(signatureWrapper.getPdfSignatureOrFormFillChanges()));
                assertEquals(1, signatureWrapper.getPdfSignatureOrFormFillChanges().stream()
                        .filter(m -> m.getValue().contains("/Rect")).count());
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));

                secondSignatureFound = true;
            }
        }
        assertTrue(firstSignatureFound);
        assertTrue(secondSignatureFound);
    }

}
