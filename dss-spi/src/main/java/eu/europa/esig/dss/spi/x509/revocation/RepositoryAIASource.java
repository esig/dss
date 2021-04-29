package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.AIASource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public abstract class RepositoryAIASource implements AIASource, Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(RepositoryAIASource.class);

    /**
     * Data source is used to access certificate tokens that are not present in the repository
     */
    protected AIASource proxiedSource;

    /**
    * Sets a source to access an AIA in case the requested certificates are not present in the repository
    *
    */
    public void setProxySource(AIASource proxiedSource) {
        this.proxiedSource = proxiedSource;
    }

    @Override
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken) {
        List<String> urls = DSSASN1Utils.getCAAccessLocations(certificateToken);

        if (Utils.isCollectionEmpty(urls)) {
            LOG.info("There is no AIA extension for certificate download.");
            return Collections.emptySet();
        }

        initRevocationTokenKeys(urls);

        return null;
    }

    /**
     * Initialize a list of AIA certificate token keys {@link String} from the given urls
     *
     * @param aiaUrls a list of {@link String} AIA urls
     * @return list of {@link String} AIA certificate keys
     */
    protected List<String> initRevocationTokenKeys(List<String> aiaUrls) {
        List<String> keys = new ArrayList<>();
        for (String url : aiaUrls) {
            keys.add(DSSUtils.getSHA1Digest(url));
        }
        return keys;
    }

}
