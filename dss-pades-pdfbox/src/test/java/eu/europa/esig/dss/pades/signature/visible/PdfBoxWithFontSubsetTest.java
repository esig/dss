package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.signature.visible.suite.PAdESWithFontSubsetTest;
import eu.europa.esig.dss.pdfa.validation.PDFADocumentValidator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdfBoxWithFontSubsetTest extends PAdESWithFontSubsetTest {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        PDFADocumentValidator validator = new PDFADocumentValidator(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        return validator;
    }

    @Override
    protected void checkPDFAInfo(DiagnosticData diagnosticData) {
        super.checkPDFAInfo(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());

        assertTrue(diagnosticData.isPDFAValidationPerformed());
        assertEquals("PDF/A-1B", diagnosticData.getPDFAProfileId());
        assertTrue(diagnosticData.isPDFACompliant());
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getPDFAValidationErrors()));
    }

}
