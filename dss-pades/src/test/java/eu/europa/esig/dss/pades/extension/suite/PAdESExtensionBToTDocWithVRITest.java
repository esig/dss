package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionBToTDocWithVRITest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        PAdESService padesService = new PAdESService(getOfflineCertificateVerifier());
        padesService.setTspSource(getGoodTsa());

        DSSDocument originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/test-with-vri.pdf"));

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        signatureParameters.setSignWithExpiredCertificate(true);

        return padesService.extendDocument(originalDocument, signatureParameters);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signatureWrapper);

        List<TimestampWrapper> vriTimestamps = signatureWrapper.getVRITimestamps();
        assertEquals(0, vriTimestamps.size());

        List<TimestampWrapper> documentTimestamps = signatureWrapper.getDocumentTimestamps();
        assertEquals(1, documentTimestamps.size());

        List<TimestampWrapper> tLevelTimestamps = signatureWrapper.getTLevelTimestamps();
        assertEquals(1, tLevelTimestamps.size());

        List<TimestampWrapper> aLevelTimestamps = signatureWrapper.getALevelTimestamps();
        assertEquals(0, aLevelTimestamps.size());

        boolean docTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
            if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(2, timestampWrapper.getTimestampedSignedData().size());
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(0, timestampWrapper.getTimestampedTimestamps().size());
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedCertificates()));
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedRevocations()));
                docTstFound = true;
            }
        }
        assertTrue(docTstFound);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
        assertNotNull(pdfRevision);
        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
        checkPdfSignatureDictionary(pdfRevision);
    }

    @Override
    protected void checkVRIDictionaryCreationTime(DiagnosticData diagnosticData) {
        super.checkVRIDictionaryCreationTime(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signatureWrapper);
        assertNotNull(signatureWrapper.getVRIDictionaryCreationTime());
    }

}
