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

public class PAdESWithSpoofingAttackTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-spoofing-attack.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
        assertNotNull(pdfRevision);
        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
        checkPdfSignatureDictionary(pdfRevision);

        assertFalse(signature.arePdfModificationsDetected());
        assertFalse(Utils.isCollectionEmpty(signature.getPdfUndefinedChanges()));
    }

    @Override
    protected void checkPdfSignatureDictionary(PDFRevisionWrapper pdfRevision) {
        assertNotNull(pdfRevision);
        assertNotNull(pdfRevision.getSignatureDictionaryType());
        assertNotNull(pdfRevision.getSubFilter());
        assertFalse(pdfRevision.isPdfSignatureDictionaryConsistent());
        checkByteRange(pdfRevision);
    }

}
