package eu.europa.esig.dss.pki.revocation.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.service.CertificateEntityService;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.revocation.OnlineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PkiCRLSource implements CRLSource {
    private static final Logger LOG = LoggerFactory.getLogger(PkiCRLSource.class);
    private static final long serialVersionUID = 6912729291417315212L;

    CertificateEntityService entityService = GenericFactory.getInstance().create(CertificateEntityService.class);

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        return getRevocationToken(certificateToken, issuerCertificateToken, Collections.emptyList());
    }

    public CRLToken getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken,
                                       List<String> alternativeUrls) {

        if (certificateToken == null) {
            return null;
        }

        if (Utils.isCollectionNotEmpty(alternativeUrls)) {
            LOG.info("CRL alternative urls : {}", alternativeUrls);
        }

        final List<String> crlAccessUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
        if (Utils.isCollectionEmpty(crlAccessUrls) && Utils.isCollectionEmpty(alternativeUrls)) {
            LOG.debug("No CRL location found for {}", certificateToken.getDSSIdAsString());
            return null;
        }
        final List<String> crlUrls = new ArrayList<>();
        crlUrls.addAll(crlAccessUrls);
        crlUrls.addAll(alternativeUrls);

        OnlineRevocationSource.RevocationTokenAndUrl<CRL> revocationTokenAndUrl = getRevocationTokenAndUrl(certificateToken, issuerToken, crlUrls);
        if (revocationTokenAndUrl != null) {
            return (CRLToken) revocationTokenAndUrl.getRevocationToken();
        } else {
            LOG.debug("No CRL has been downloaded for a CertificateToken with Id '{}' from a list of urls : {}",
                    certificateToken.getDSSIdAsString(), crlUrls);
            return null;
        }
    }


    /**
     * Extracts a CRL token for a {@code certificateToken} from the given list of {@code crlUrls}
     *
     * @param certificateToken {@link CertificateToken} to get a CRL token for
     * @param issuerToken      {@link CertificateToken} issued the {@code certificateToken}
     * @param crlUrls          a list of {@link String} URLs to use to access a CRL token
     * @return {@link OnlineRevocationSource.RevocationTokenAndUrl}
     */
    protected OnlineRevocationSource.RevocationTokenAndUrl<CRL> getRevocationTokenAndUrl(CertificateToken certificateToken,
                                                                                         CertificateToken issuerToken, List<String> crlUrls) {

        if (issuerToken == null) {
            return null;
        }
        if (Utils.isCollectionEmpty(crlUrls)) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Trying to retrieve a CRL from URL(s) {}...", crlUrls);
        }
        final DataLoader.DataAndUrl dataAndUrl = downloadCrl(crlUrls);
        if (dataAndUrl == null) {
            return null;
        }
        try {
            CRLBinary crlBinary = CRLUtils.buildCRLBinary(dataAndUrl.getData());
            final CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerToken);
            final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
            crlToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
            crlToken.setSourceURL(dataAndUrl.getUrlString());
            if (LOG.isDebugEnabled()) {
                LOG.debug("CRL '{}' has been retrieved from a source with URL '{}'.",
                        crlToken.getDSSIdAsString(), dataAndUrl.getUrlString());
            }
            return new OnlineRevocationSource.RevocationTokenAndUrl<>(dataAndUrl.getUrlString(), crlToken);

        } catch (Exception e) {
            LOG.warn("Unable to parse/validate the CRL (url: {}) : {}", dataAndUrl.getUrlString(), e.getMessage(), e);
            return null;
        }
    }

    /**
     * Download a CRL from any location with any protocol.
     *
     * @param downloadUrls the {@code List} of urls to be used to obtain the revocation
     *                     data through the CRL canal.
     * @return {@code X509CRL} or null if it was not possible to download the
     * CRL
     */
    private DataLoader.DataAndUrl downloadCrl(final List<String> downloadUrls) {
        try {
            return entityService.getByCrlUrl(downloadUrls);

        } catch (DSSException e) {
            LOG.warn("Unable to download CRL from URLs [{}]. Reason : [{}]", downloadUrls, e.getMessage(), e);
            return null;
        }
    }


}
