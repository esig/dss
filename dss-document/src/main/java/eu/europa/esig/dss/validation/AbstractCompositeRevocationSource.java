package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract class specifying the main methods for revocation token loading and verification
 *
 */
public abstract class AbstractCompositeRevocationSource implements CompositeRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractCompositeRevocationSource.class);

    /**
     * The CRL revocation source
     */
    private RevocationSource<CRL> crlSource;

    /**
     * The OCSP revocation source
     */
    private RevocationSource<OCSP> ocspSource;

    /**
     * The trusted certificate source is used to accept trusted OCSPToken's certificate issuers
     */
    private ListCertificateSource trustedListCertificateSource;

    @Override
    public void setCrlSource(RevocationSource<CRL> crlSource) {
        this.crlSource = crlSource;
    }

    @Override
    public void setOcspSource(RevocationSource<OCSP> ocspSource) {
        this.ocspSource = ocspSource;
    }

    @Override
    public void setTrustedCertificateSource(ListCertificateSource trustedListCertificateSource) {
        this.trustedListCertificateSource = trustedListCertificateSource;
    }

    /**
     * Retrieves and verifies the obtained CRL token
     *
     * NOTE: returns only if a valid entry has been obtained!
     *
     * @param certificateToken {@link CertificateToken} to get CRL for
     * @param issuerToken {@link CertificateToken} issuer of {@code certificateToken}
     * @return {@link RevocationToken}
     */
    protected RevocationToken<CRL> checkCRL(final CertificateToken certificateToken, final CertificateToken issuerToken) {
        if (crlSource == null) {
            LOG.debug("CRLSource is null");
            return null;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("CRL request for: {} using: {}", certificateToken.getDSSIdAsString(), crlSource.getClass().getSimpleName());
        }
        try {
            final RevocationToken<CRL> revocationToken = crlSource.getRevocationToken(certificateToken, issuerToken);
            if (revocationToken != null && containsCertificateStatus(revocationToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("CRL for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocationToken.getAbbreviation());
                }
                return revocationToken;
            }
        } catch (DSSException e) {
            LOG.error("CRL DSS Exception: {}", e.getMessage(), e);
            return null;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("A CRL for token {} is not obtained! Return null value.", certificateToken.getDSSIdAsString());
        }
        return null;
    }

    /**
     * Retrieves and verifies the obtained OCSP token
     *
     * NOTE: returns only if a valid entry has been obtained!
     *
     * @param certificateToken {@link CertificateToken} to get OCSP for
     * @param issuerToken {@link CertificateToken} issuer of {@code certificateToken}
     * @return {@link RevocationToken}
     */
    protected RevocationToken<OCSP> checkOCSP(final CertificateToken certificateToken, final CertificateToken issuerToken) {
        if (ocspSource == null) {
            LOG.debug("OCSPSource null");
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OCSP request for: {} using: {}", certificateToken.getDSSIdAsString(), ocspSource.getClass().getSimpleName());
        }
        try {
            final RevocationToken<OCSP> revocationToken = ocspSource.getRevocationToken(certificateToken, issuerToken);
            if (revocationToken != null && containsCertificateStatus(revocationToken) && isAcceptable(revocationToken)
                    && isIssuerValidAtRevocationProductionTime(revocationToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("OCSP response for {} retrieved: {}", certificateToken.getDSSIdAsString(), revocationToken.getAbbreviation());
                    LOG.debug("OCSP Response {} status is : {}", revocationToken.getDSSIdAsString(), revocationToken.getStatus());
                }
                return revocationToken;
            }
        } catch (DSSException e) {
            LOG.error("OCSP DSS Exception: {}", e.getMessage(), e);
            return null;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("An OCSP response for token {} is not obtained! Return null value.", certificateToken.getDSSIdAsString());
        }
        return null;
    }

    private boolean containsCertificateStatus(RevocationToken<?> revocationToken) {
        if (revocationToken.getStatus() == null) {
            LOG.warn("The obtained revocation token does not contain the certificate status. "
                    + "The token is skipped.");
            return false;
        }
        return true;
    }

    private boolean isAcceptable(RevocationToken<OCSP> ocspToken) {
        CertificateToken issuerCertificateToken = ocspToken.getIssuerCertificateToken();
        if (issuerCertificateToken == null) {
            LOG.warn("The issuer certificate is not found for the obtained OCSPToken. "
                    + "The token is skipped.");
            return false;

        } else if (doesRequireRevocation(issuerCertificateToken) && !hasRevocationAccessPoints(issuerCertificateToken)) {
            LOG.warn("The issuer certificate of the obtained OCSPToken requires a revocation data, "
                    + "which is not acceptable due its configuration (no revocation access location points). The token is skipped.");
            return false;

        }
        return true;
    }

    private boolean doesRequireRevocation(final CertificateToken certificateToken) {
        if (certificateToken.isSelfSigned()) {
            return false;
        }
        if (isTrusted(certificateToken)) {
            return false;
        }
        if (DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certificateToken)) {
            return false;
        }
        return true;
    }

    private boolean isTrusted(CertificateToken certificateToken) {
        return trustedListCertificateSource != null && trustedListCertificateSource.isTrusted(certificateToken);
    }

    private boolean hasRevocationAccessPoints(final CertificateToken certificateToken) {
        if (Utils.isCollectionNotEmpty(DSSASN1Utils.getOCSPAccessLocations(certificateToken))) {
            return true;
        }
        if (Utils.isCollectionNotEmpty(DSSASN1Utils.getCrlUrls(certificateToken))) {
            return true;
        }
        return false;
    }

    private boolean isIssuerValidAtRevocationProductionTime(RevocationToken<?> revocationToken) {
        if (!DSSRevocationUtils.checkIssuerValidAtRevocationProductionTime(revocationToken)) {
            LOG.warn("The revocation token has been produced outside the issuer certificate's validity range. "
                    + "The token is skipped.");
            return false;
        }
        return true;
    }

}
