package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdfBoxDSS2236HideTest extends DSS2236HideTest {

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
        assertTrue(pdfRevision.arePdfModificationsDetected());

        assertEquals(1, pdfRevision.getPdfVisualDifferenceConcernedPages().size());
        assertEquals(1, pdfRevision.getPdfVisualDifferenceConcernedPages().get(0).intValue());
    }

}
