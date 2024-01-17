/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract repository AIA source
 */
public abstract class RepositoryAIASource implements AIASource {

    private static final long serialVersionUID = -8629948836670094079L;

    private static final Logger LOG = LoggerFactory.getLogger(RepositoryAIASource.class);

    /**
     * Data source is used to access certificate tokens that are not present in the repository
     */
    protected AIASource proxiedSource;

    /**
     * Default constructor instantiating object with null proxied source
     */
    protected RepositoryAIASource() {
        // empty
    }

    /**
     * Sets a source to access an AIA in case the requested certificates are not present in the repository
     *
     * @param proxiedSource {@link AIASource}
     *                      a source to be used to download the data when no relevant certificates is found in the repository
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
     * @param forceRefresh     defines should the related certificates be refreshed within the source
     * @return a set if {@link CertificateToken}s
     */
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken, boolean forceRefresh) {
        Objects.requireNonNull(certificateToken, "CertificateToken shall be provided!");
        List<String> urls = CertificateExtensionsUtils.getCAIssuersAccessUrls(certificateToken);
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
                LOG.info("Certificate tokens with AIA '{}' have been loaded from the cache", urls);
                return aiaCertificates;
            }
        }

        return extractAndInsertCertificatesFromProxiedSource(certificateToken, aiaKeys);
    }

    /**
     * Extracts a set of {@code CertificateToken}s from the defined proxiedSource and inserts/updates values
     * in the cache source if required.
     *
     * @param certificateToken {@link CertificateToken} to extract the AIA certificates for
     * @param aiaKeys          - list of keys that can be used as unique identifications of the revocation entry
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

        final Set<CertificateToken> result = new HashSet<>();

        Set<CertificateToken> certificatesTokenByAIA = proxiedSource.getCertificatesByAIA(certificateToken);
        if (Utils.isCollectionNotEmpty(certificatesTokenByAIA)) {
            for (CertificateToken certificate : certificatesTokenByAIA) {
                String sourceUrl = getCertificateTokenAIAUrl(certificate);
                if (sourceUrl == null) {
                    LOG.warn("Not able to find AIA CA issuers URL for certificate '{}'. CA issuers will not be added to the cache.", certificateToken.getDSSIdAsString());
                    return certificatesTokenByAIA;
                }
                String aiaKey = getAIAKey(sourceUrl);
                insertCertificate(aiaKey, certificate);
                result.add(certificate);
            }
            LOG.info("CA issuers for a certificate with Id '{}' are added into the cache", certificateToken.getDSSIdAsString());
        }

        return result;
    }

    /**
     * Returns a caIssuers access URL
     *
     * @param certificateToken {@link CertificateToken}
     * @return {@link String}
     */
    protected String getCertificateTokenAIAUrl(CertificateToken certificateToken) {
        String sourceUrl = certificateToken.getSourceURL();
        if (sourceUrl == null) {
            List<String> aiaUrls = CertificateExtensionsUtils.getCAIssuersAccessUrls(certificateToken);
            if (aiaUrls.size() == 0) {
                LOG.warn("No AIA distribution points have been found for this certificate Token with ID {} ", certificateToken.getDSSIdAsString());
            } else if (aiaUrls.size() == 1) {
                sourceUrl = aiaUrls.get(0);
            } else {
                sourceUrl = aiaUrls.get(0);
                LOG.debug("There are multiple AIA distribution points for certificate token with ID {} , the first url will be used as Jdbc revocation source key", certificateToken.getDSSIdAsString());
            }
        }
        return sourceUrl;
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
            keys.add(getAIAKey(url));
        }
        return keys;
    }

    /**
     * Creates a key corresponding to the given {@code aiaUrl}
     *
     * @param aiaUrl {@link String} URL
     * @return {@link String} key
     */
    protected String getAIAKey(final String aiaUrl) {
        return DSSUtils.getSHA1Digest(aiaUrl);
    }

    /**
     * Generates a unique identifier for the {@code CertificateToken} and {@code aiaUrl} pair
     *
     * @param certificateToken {@link CertificateToken}
     * @param aiaUrl {@link String}
     * @return {@link String}
     */
    protected String getUniqueCertificateAiaId(final CertificateToken certificateToken, String aiaUrl) {
        return DSSUtils.getSHA1Digest(certificateToken.getDSSIdAsString() + aiaUrl);
    }

    private Set<CertificateToken> extractAIAFromCacheSource(List<String> aiaKeys) {
        Set<CertificateToken> certificateTokens = new LinkedHashSet<>();
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
     * @param aiaKey           {@link String} AIA key identifying an AIA access URL
     * @param certificateToken {@link CertificateToken} to insert
     */
    protected abstract void insertCertificate(final String aiaKey, final CertificateToken certificateToken);

    /**
     * This method removes the certificates from DB with the given aiaKey
     *
     * @param aiaKey {@link String} representing an AIA URL identifier
     */
    protected abstract void removeCertificates(final String aiaKey);

}
