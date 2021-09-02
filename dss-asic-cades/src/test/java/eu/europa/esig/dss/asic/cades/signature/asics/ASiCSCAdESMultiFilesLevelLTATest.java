package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSCAdESMultiFilesLevelLTATest extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSigns = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentsToSigns.add(new FileDocument("src/test/resources/signable/test.zip"));
        documentsToSigns.add(new FileDocument("src/test/resources/signable/test.txt"));

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(2, diagnosticData.getTimestampList().size());

        boolean sigTstFound = false;
        boolean archiveTimestampFound = false;
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(0, timestamp.getTimestampScopes().size());
                assertEquals(3, timestamp.getTimestampedSignedData().size()); // two signed docs + package.zip
                sigTstFound = true;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(3, timestamp.getTimestampScopes().size());
                assertEquals(3, timestamp.getTimestampedSignedData().size());
                assertEquals(1, timestamp.getTimestampedSignatures().size());
                archiveTimestampFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(archiveTimestampFound);
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.ASICS;
    }

    @Override
    protected boolean isBaselineT() {
        return true;
    }

    @Override
    protected boolean isBaselineLTA() {
        return true;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSigns;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
