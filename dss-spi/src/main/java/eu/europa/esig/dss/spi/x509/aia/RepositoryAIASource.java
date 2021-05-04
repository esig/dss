package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract repository AIA source
 *
 */
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
       return getCertificatesByAIA(certificateToken, false);
    }

    /**
     * This method allows to populate the source with new AIA certificates obtained from an proxied source,
     * by forcing the refresh
     *
     * @param certificateToken {@link CertificateToken} to get certificate chain by AIA for
     * @param forceRefresh defines should the related certificates be refreshed within the source
     * @return a set if {@link CertificateToken}s
     */
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken, boolean forceRefresh) {
        Objects.requireNonNull(certificateToken, "CertificateToken shall be provided!");

        List<String> urls = DSSASN1Utils.getCAAccessLocations(certificateToken);
        if (Utils.isCollectionEmpty(urls)) {
            LOG.info("There is no AIA extension for certificate download.");
            return Collections.emptySet();
        }

        List<String> aiaKeys = initCertificateAIAKeys(urls);
        if (forceRefresh) {
            LOG.info("Cache is skipped to retrieve the certificates by AIA for the certificate with Id '{}'",
                    certificateToken.getDSSIdAsString());
        } else {
            Set<CertificateToken> aiaCertificates = extractAIAFromCacheSource(aiaKeys);
            if (Utils.isCollectionNotEmpty(aiaCertificates)) {
                return aiaCertificates;
            }
        }

        return extractAndInsertCertificatesFromProxiedSource(certificateToken, aiaKeys);
    }

    /**
     * Extracts a set of {@code CertificateToken}s from the defined proxiedSource and inserts/updates its
     * in the cache source if required.
     *
     * @param certificateToken {@link CertificateToken} to extract the AIA certificates for
     * @param aiaKeys - list of keys that can be used as unique identifications of the revocation entry
     * @return a set of {@link CertificateToken}s
     */
    private Set<CertificateToken> extractAndInsertCertificatesFromProxiedSource(final CertificateToken certificateToken,
                                                                                List<String> aiaKeys) {
        if (proxiedSource == null) {
            LOG.warn("Proxied AIASource is not provided!");
            return Collections.emptySet();
        }

        List<String> existingAIAKeys = getExistingAIAKeys();
        for (String aiaKey : aiaKeys) {
            if (existingAIAKeys.contains(aiaKey)) {
                LOG.info("AIA Certificates with key '{}' have been removed from DB", aiaKey);
                removeCertificates(aiaKey);
            }
        }

        Set<CertificateToken> certificatesByAIA = proxiedSource.getCertificatesByAIA(certificateToken);
        if (Utils.isCollectionNotEmpty(certificatesByAIA)) {
            for (CertificateToken aiaCertificate : certificatesByAIA) {
                LOG.info("AIA Certificate token with Id '{}' is added into the cache", aiaCertificate.getDSSIdAsString());
                insertCertificate(aiaCertificate);
            }
        }
        return certificatesByAIA;
    }

    /**
     * Returns a list of all existing AIA keys present in the DB
     *
     * @return a list of {@link String} AIA keys
     */
    protected abstract List<String> getExistingAIAKeys();

    /**
     * Initialize a list of AIA certificate token keys {@link String} from the given urls
     *
     * @param aiaUrls a list of {@link String} AIA urls
     * @return list of {@link String} AIA certificate keys
     */
    protected List<String> initCertificateAIAKeys(List<String> aiaUrls) {
        List<String> keys = new ArrayList<>();
        for (String url : aiaUrls) {
            keys.add(DSSUtils.getSHA1Digest(url));
        }
        return keys;
    }

    private Set<CertificateToken> extractAIAFromCacheSource(List<String> aiaKeys) {
        Set<CertificateToken> certificateTokens = new HashSet<>();
        for (String key : aiaKeys) {
            certificateTokens.addAll(findCertificates(key));
        }
        return certificateTokens;
    }

    /**
     * This method returns a set of certificates from a DB with the given key
     *
     * @param key {@link String} the aiaKey to extract certificates by
     * @return a set of {@link CertificateToken}s
     */
    protected abstract Set<CertificateToken> findCertificates(final String key);

    /**
     * This method allows inserting of a certificate into the DB
     *
     * @param aiaCertificate {@link CertificateToken} to insert
     */
    protected abstract void insertCertificate(final CertificateToken aiaCertificate);

    /**
     * This method removes the certificates from DB with the given aiaKey
     *
     * @param aiaKey {@link String} representing an AIA URL identifier
     */
    protected abstract void removeCertificates(final String aiaKey);

}
