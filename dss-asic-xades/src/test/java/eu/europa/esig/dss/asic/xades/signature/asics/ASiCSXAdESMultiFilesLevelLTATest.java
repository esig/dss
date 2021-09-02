package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCWithXAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSXAdESMultiFilesLevelLTATest extends AbstractASiCWithXAdESMultipleDocumentsTestSignature {

    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSigns = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentsToSigns.add(new FileDocument("src/test/resources/signable/open-document.odt"));
        documentsToSigns.add(new FileDocument("src/test/resources/signable/test.txt"));

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
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
                assertEquals(3, timestamp.getTimestampedSignedData().size());
                sigTstFound = true;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(3, timestamp.getTimestampScopes().size()); // two signed docs + package.zip
                assertEquals(3, timestamp.getTimestampedSignedData().size());
                archiveTimestampFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(archiveTimestampFound);
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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
    protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
