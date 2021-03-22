package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class fetches firstly OCSP token response, if not available, tries CRL and returns the first succeeded result
 *
 * NOTE: This implementation is use by default for revocation retrieving
 *
 */
public class OCSPFirstAndCRLRevocationSource extends AbstractCompositeRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(OCSPFirstAndCRLRevocationSource.class);

    @Override
    public RevocationToken<Revocation> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        RevocationToken result = checkOCSP(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        result = checkCRL(certificateToken, issuerToken);
        if (result != null) {
            return result;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("There is no response for {} neither from OCSP nor from CRL!", certificateToken.getDSSIdAsString());
        }
        return null;
    }

}
