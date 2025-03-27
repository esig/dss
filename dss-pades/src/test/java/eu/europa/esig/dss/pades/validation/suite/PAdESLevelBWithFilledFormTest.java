package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESLevelBWithFilledFormTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-signed-filled-form.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
        assertNotNull(pdfRevision);

        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
        checkPdfSignatureDictionary(pdfRevision);

        assertTrue(signature.arePdfModificationsDetected());
        assertFalse(Utils.isCollectionEmpty(signature.getPdfExtensionChanges()));
        assertFalse(Utils.isCollectionEmpty(signature.getPdfSignatureOrFormFillChanges()));
        assertTrue(Utils.isCollectionEmpty(signature.getPdfAnnotationChanges()));
        assertTrue(Utils.isCollectionEmpty(signature.getPdfUndefinedChanges()));
    }

}
