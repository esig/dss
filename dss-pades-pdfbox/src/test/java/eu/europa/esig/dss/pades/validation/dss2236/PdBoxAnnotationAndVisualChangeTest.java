package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdBoxAnnotationAndVisualChangeTest extends AnnotationAndVisualChangeTest {

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        boolean firstSignatureFound = false;
        boolean secondSignatureFound = false;
        boolean thirdSignatureFound = false;

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertTrue(signature.arePdfModificationsDetected());

            PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
            assertNotNull(pdfRevision);
            assertTrue(pdfRevision.arePdfModificationsDetected());

            if (Utils.isCollectionNotEmpty(pdfRevision.getPdfVisualDifferenceConcernedPages())) {
                assertEquals(1, pdfRevision.getPdfVisualDifferenceConcernedPages().size());
                assertEquals(2, pdfRevision.getPdfVisualDifferenceConcernedPages().get(0).intValue());

                firstSignatureFound = true;

            } else if (pdfRevision.arePdfObjectModificationsDetected()) {
                secondSignatureFound = true;

            } else {
                thirdSignatureFound = true;
            }
        }

        assertTrue(firstSignatureFound);
        assertTrue(secondSignatureFound);
        assertTrue(thirdSignatureFound);
    }

}
