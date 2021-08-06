package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESExtensionBToLTWithRevokedCertTest extends AbstractXAdESTestExtension {

    private XAdESSignatureParameters signatureParameters;
    private XAdESSignatureParameters extensionParameters;

    @BeforeEach
    public void init() {
        signatureParameters = super.getSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(false);

        extensionParameters = super.getExtensionParameters();
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LT;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected XAdESSignatureParameters getExtensionParameters() {
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        extensionParameters.setCheckCertificateRevocation(true);
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        XAdESService xadesService = new XAdESService(completeCertificateVerifier);
        xadesService.setTspSource(getUsedTSPSourceAtExtensionTime());
        return xadesService.extendDocument(signedDocument, getExtensionParameters());
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}
