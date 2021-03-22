package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class fetches firstly CRL response, if not available, tries OCSP and returns the first succeeded result
 *
 */
public class CRLFirstAndOCSPRevocationSource extends AbstractCompositeRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(CRLFirstAndOCSPRevocationSource.class);

    @Override
    public RevocationToken<Revocation> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        RevocationToken result = checkCRL(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        result = checkOCSP(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("There is no response for {} neither from CRL nor from OCSP!", certificateToken.getDSSIdAsString());
        }
        return null;
    }

}
