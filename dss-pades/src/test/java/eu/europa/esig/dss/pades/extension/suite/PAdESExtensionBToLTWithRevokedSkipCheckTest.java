package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class PAdESExtensionBToLTWithRevokedSkipCheckTest extends AbstractPAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LT;
    }

    @Override
    protected PAdESService getSignatureServiceToExtend() {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert());
        PAdESService service = new PAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}
