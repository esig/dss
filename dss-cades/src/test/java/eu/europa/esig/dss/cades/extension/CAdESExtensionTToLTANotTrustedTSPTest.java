package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESExtensionTToLTANotTrustedTSPTest extends AbstractCAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getSHA3GoodTsa();
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setDataLoader(new CommonsDataLoader());
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setOcspSource(new OnlineOCSPSource());

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.importAsTrusted(getBelgiumTrustAnchors());
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);

        CAdESService service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());

        return service;
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> super.extendAndVerify());
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));
        assertTrue(exception.getMessage().contains("Revocation data is skipped for untrusted certificate chain for the token :"));
    }

}
