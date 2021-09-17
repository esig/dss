package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESExtensionBToLTAWithExpiredUserTest extends AbstractJAdESTestExtension {

    private JAdESService service;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setSignWithExpiredCertificate(true);
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        JAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setSignWithExpiredCertificate(true);
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("The signing certificate has been expired and " +
                "there is no POE during its validity range."));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MONTH, -6);
        Date tstTime = calendar.getTime();

        service.setTspSource(getGoodTsaByTime(tstTime));

        DSSDocument extendedDocument = super.extendSignature(signedDocument);
        assertNotNull(extendedDocument);

        service.setTspSource(getGoodTsa());

        extendedDocument = super.extendSignature(extendedDocument);
        assertNotNull(extendedDocument);
        return extendedDocument;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        if (SignatureLevel.JAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
            List<TimestampWrapper> timestampList = signature.getTimestampList();
            assertEquals(3, timestampList.size());
            int signatureTstCounter = 0;
            int archiveTstCounter = 0;
            for (TimestampWrapper timestampWrapper : timestampList) {
                if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                    ++signatureTstCounter;
                } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                    ++archiveTstCounter;
                }
            }
            assertEquals(1, signatureTstCounter);
            assertEquals(2, archiveTstCounter);
        }
    }

    @Override
    protected JAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

}
