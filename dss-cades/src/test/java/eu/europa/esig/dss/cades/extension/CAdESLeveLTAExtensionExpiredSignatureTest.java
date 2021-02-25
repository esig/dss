package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2369
public class CAdESLeveLTAExtensionExpiredSignatureTest extends AbstractCAdESTestExtension {

    private DSSDocument document;
    private CAdESService service;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    public void init() {
        document = new FileDocument("src/test/resources/validation/Signature-C-CZ_SIX-1.p7m");

        certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(document));
        assertTrue( exception.getMessage().contains(
                "The signing certificate has been expired and there is no POE during its validity range."));

        certificateVerifier.setAlertOnExpiredSignature(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(document);
        verify(extendedDocument);
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int arcTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());
            if (timestampWrapper.getType().isArchivalTimestamp()) {
                ++arcTstCounter;
            }
        }
        assertEquals(2, arcTstCounter);
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

}
