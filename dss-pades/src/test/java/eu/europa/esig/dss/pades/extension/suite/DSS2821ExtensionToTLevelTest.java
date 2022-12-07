package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2821ExtensionToTLevelTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2821.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        return service.extendDocument(dssDocument, parameters);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.arePdfObjectModificationsDetected());
        assertTrue(Utils.isCollectionNotEmpty(signature.getPdfExtensionChanges()));
        assertTrue(Utils.isCollectionNotEmpty(signature.getPdfSignatureOrFormFillChanges()));
        assertFalse(Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()));
        assertFalse(Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges()));

        TimestampWrapper detachedTst = diagnosticData.getTimestampList().get(0);
        assertFalse(Utils.isCollectionNotEmpty(detachedTst.getTimestampedSignatures()));

        assertTrue(detachedTst.arePdfObjectModificationsDetected());
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfExtensionChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfSignatureOrFormFillChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfAnnotationChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfUndefinedChanges()));

        TimestampWrapper docTst = diagnosticData.getTimestampList().get(1);
        assertTrue(Utils.isCollectionNotEmpty(docTst.getTimestampedSignatures()));
        assertFalse(docTst.arePdfObjectModificationsDetected());
    }

}
