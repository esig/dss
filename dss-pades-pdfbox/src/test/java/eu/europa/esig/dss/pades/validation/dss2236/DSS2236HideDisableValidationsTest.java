package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetectionUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DSS2236HideDisableValidationsTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2236/hide.pdf"));
    }

    @BeforeAll
    public static void init() {
        PdfModificationDetectionUtils pdfModificationDetectionUtils = PdfModificationDetectionUtils.getInstance();

        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0);
        pdfModificationDetectionUtils.setPdfDifferencesFinder(pdfDifferencesFinder);

        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(5);
        pdfModificationDetectionUtils.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        XmlPDFRevision pdfRevision = signature.getPDFRevision();

        XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
        assertNull(modificationDetection);

        assertFalse(signature.arePdfModificationsDetected());
        assertFalse(signature.arePdfObjectModificationsDetected());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
    }

    @AfterAll
    public static void clean() {
        PdfModificationDetectionUtils pdfModificationDetectionUtils = PdfModificationDetectionUtils.getInstance();
        pdfModificationDetectionUtils.setPdfDifferencesFinder(new DefaultPdfDifferencesFinder());
        pdfModificationDetectionUtils.setPdfObjectModificationsFinder(new DefaultPdfObjectModificationsFinder());
    }

}
