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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Allows storing and retrieving of revocation data to/from a repository
 * (e.g. database)
 *
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class RepositoryRevocationSource<R extends Revocation> implements RevocationSource<R>, MultipleRevocationSource<R> {

    private static final Logger LOG = LoggerFactory.getLogger(RepositoryRevocationSource.class);

    private static final long serialVersionUID = 8116937707098957391L;

    /**
     * Data source used to access a revocation token that is not present in the repository
     */
    protected RevocationSource<R> proxiedSource;

    /**
     * Default cache delay in case of null nextUpdate in the revocation data
     */
    private Long defaultNextUpdateDelay;

    /**
     * Maximum cache delay for the revocation data
     */
    private Long maxNextUpdateDelay;

    /**
     * If true, removes revocation tokens from DB with nextUpdate before the current date
     */
    private boolean removeExpired = true;

    /**
     * Default constructor instantiating object with null values
     */
    protected RepositoryRevocationSource() {
        // empty
    }

    /**
     * Initialize a list of revocation token keys {@link String} from the given {@link CertificateToken}
     *
     * @param certificateToken {@link CertificateToken}
     * @return list of {@link String} revocation keys
     */
    protected abstract List<String> initRevocationTokenKeys(CertificateToken certificateToken);

    /**
     * Finds a list of RevocationTokens in the cache for the given {@code certificateToken}
     * with the corresponding {@code key}
     *
     * @param key              the key {@link String}
     * @param certificateToken {@link CertificateToken}
     * @param issuerCertToken  {@link CertificateToken}
     * @return a list of {@link RevocationToken} objects
     */
    protected abstract List<RevocationToken<R>> findRevocations(final String key, final CertificateToken certificateToken,
                                                                final CertificateToken issuerCertToken);

    /**
     * Inserts a new RevocationToken into the cache
     *
     * @param revocationKey {@link String}
     * @param token         {@link RevocationToken}
     */
    protected abstract void insertRevocation(final String revocationKey, final RevocationToken<R> token);

    /**
     * Updates the RevocationToken into cache
     *
     * @param revocationKey {@link String}
     * @param token         {@link RevocationToken}
     */
    protected abstract void updateRevocation(final String revocationKey, final RevocationToken<R> token);

    /**
     * Removes the RevocationToken from cache with the given key
     *
     * @param revocationKey {@link String}
     */
    protected abstract void removeRevocation(final String revocationKey);

    /**
     * Sets the default next update delay for the cached files in seconds. If
     * more time has passed from the revocation token's thisUpdate and next update
     * time is not specified, then a fresh copy is downloaded and cached, otherwise
     * a cached copy is used.
     * <p>
     * {@code
     * If revocation.nextUpdate = null, then nextUpdate = revocation.thisUpdate + defaultNextUpdateDelay
     * }
     *
     * @param defaultNextUpdateDelay long value (seconds)
     */
    public void setDefaultNextUpdateDelay(final Long defaultNextUpdateDelay) {
        this.defaultNextUpdateDelay = defaultNextUpdateDelay == null ? null : defaultNextUpdateDelay * 1000; // to milliseconds
    }

    /**
     * Sets the maximum allowed nextUpdate delay for cached files in seconds.
     * Allows to force refresh in case of long periods between revocation
     * publication (eg : 6 months for ARL).
     * <p>
     * {@code
     * If revocation.nextUpdate > revocation.thisUpdate + maxNextUpdateDelay, then nextUpdate = revocation.thisUpdate + maxNextUpdateDelay
     * }
     *
     * @param maxNextUpdateDelay long value (seconds)
     */
    public void setMaxNextUpdateDelay(final Long maxNextUpdateDelay) {
        this.maxNextUpdateDelay = maxNextUpdateDelay == null ? null : maxNextUpdateDelay * 1000; // to milliseconds
    }

    /**
     * The proxied revocation source to be called if the data is not available in
     * the cache
     *
     * @param proxiedSource the proxiedSource to set
     */
    public void setProxySource(final RevocationSource<R> proxiedSource) {
        this.proxiedSource = proxiedSource;
    }

    /**
     * Sets whether the expired revocation data shall be removed from the cache
     * <p>
     * Default : TRUE (expired revocation data is being removed from the cache)
     *
     * @param removeExpired the removeExpired to set
     */
    public void setRemoveExpired(boolean removeExpired) {
        this.removeExpired = removeExpired;
    }

    @Override
    public RevocationToken<R> getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
        return getRevocationToken(certificateToken, issuerCertificateToken, false);
    }

    /**
     * Retrieves a revocation token for the given {@link CertificateToken}
     *
     * @param certificateToken       {@link CertificateToken}
     * @param issuerCertificateToken {@link CertificateToken} of the issuer of
     *                               certificateToken
     * @param forceRefresh           if true, explicitly skips the cache
     * @return {@link RevocationToken}
     */
    public RevocationToken<R> getRevocationToken(final CertificateToken certificateToken,
                                                 final CertificateToken issuerCertificateToken, boolean forceRefresh) {
        List<RevocationToken<R>> revocationTokens = getRevocationTokens(certificateToken, issuerCertificateToken, forceRefresh);
        if (Utils.isCollectionNotEmpty(revocationTokens)) {
            if (Utils.collectionSize(revocationTokens) == 1) {
                return revocationTokens.iterator().next();
            } else {
                LOG.info("More than one revocation token has been found for certificate with Id '{}'. " +
                        "Return the latest revocation data.", certificateToken.getDSSIdAsString());
                return getLatestRevocationData(revocationTokens);
            }
        }
        return null;
    }

    @Override
    public List<RevocationToken<R>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        return getRevocationTokens(certificateToken, issuerCertificateToken, false);
    }

    /**
     * Retrieves a list of revocation token for the given {@link CertificateToken}
     *
     * @param certificateToken       {@link CertificateToken}
     * @param issuerCertificateToken {@link CertificateToken} of the issuer of
     *                               certificateToken
     * @param forceRefresh           if true, explicitly skips the cache
     * @return a list of {@link RevocationToken}s
     */
    public List<RevocationToken<R>> getRevocationTokens(final CertificateToken certificateToken,
                                                        final CertificateToken issuerCertificateToken, boolean forceRefresh) {
        if (certificateToken == null || issuerCertificateToken == null) {
            LOG.warn("Certificate token or issuer's certificate token is null. Cannot get a revocation token!");
            return null;
        }

        Collection<String> keys = initRevocationTokenKeys(certificateToken);
        if (forceRefresh) {
            LOG.info("Cache is skipped to retrieve the revocation token for certificate with Id '{}'",
                    certificateToken.getDSSIdAsString());
        } else {
            final Map<String, List<RevocationToken<R>>> cachedRevocationTokensMap =
                    extractRevocationFromCacheSource(certificateToken, issuerCertificateToken, keys);
            keys = cachedRevocationTokensMap.keySet(); // override with returned keys
            if (Utils.isMapNotEmpty(cachedRevocationTokensMap)) {
                // add all extracted revocation values to a single List
                return cachedRevocationTokensMap.values().stream().flatMap(Collection::stream).collect(Collectors.toList());
            }
        }

        final RevocationToken<R> revocationToken = extractAndInsertRevocationTokenFromProxiedSource(
                certificateToken, issuerCertificateToken, keys);
        if (revocationToken != null) {
            return Collections.singletonList(revocationToken);
        }
        return Collections.emptyList();
    }

    /**
     * Returns a map of correspondence between requested revocation {@code keys} and extracted revocation data tokens.
     * The map contains entries only for keys with available and still fresh revocation data.
     *
     * @param certificateToken       {@link CertificateToken} to extract the revocation token for
     * @param issuerCertificateToken {@link CertificateToken} of the issuer
     * @param keys                   a collection of {@link String} keys,
     *                               that can be used as unique identifications of the revocation entry
     * @return a map between {@link String} keys and list of {@link RevocationToken}s
     */
    private Map<String, List<RevocationToken<R>>> extractRevocationFromCacheSource(
            final CertificateToken certificateToken, final CertificateToken issuerCertificateToken, Collection<String> keys) {
        final Map<String, List<RevocationToken<R>>> result = new HashMap<>();
        for (String key : keys) {
            final List<RevocationToken<R>> revocationTokens = findRevocations(key, certificateToken, issuerCertificateToken);
            if (Utils.isCollectionNotEmpty(revocationTokens)) {
                final List<RevocationToken<R>> freshRevocationData = revocationTokens.stream()
                        .filter(r -> isNotExpired(r, issuerCertificateToken)).collect(Collectors.toList());
                if (Utils.isCollectionNotEmpty(freshRevocationData)) {
                    result.put(key, freshRevocationData);
                } else {
                    LOG.debug("Revocation token is expired in the cache for certificate with Id '{}'",
                            certificateToken.getDSSIdAsString());
                    if (removeExpired) {
                        removeRevocation(key);
                    }
                }
            }
        }
        if (Utils.isMapNotEmpty(result)) {
            LOG.info("Revocation token for certificate with Id '{}' has been loaded from the cache",
                    certificateToken.getDSSIdAsString());
        }
        return result;
    }

    private RevocationToken<R> getLatestRevocationData(Collection<RevocationToken<R>> revocationTokens) {
        RevocationToken<R> latestRevocationData = null;
        if (Utils.isCollectionNotEmpty(revocationTokens)) {
            for (RevocationToken<R> revocationToken : revocationTokens) {
                if (latestRevocationData == null || (revocationToken.getThisUpdate() != null &&
                        latestRevocationData.getThisUpdate().before(revocationToken.getThisUpdate()))) {
                    latestRevocationData = revocationToken;
                }
            }
        }
        return latestRevocationData;
    }

    /**
     * Extracts a {@link RevocationToken} from the defined proxiedSource and inserts/updates its
     * in the cache source if required.
     *
     * @param certificateToken       {@link CertificateToken} to extract the revocation token for
     * @param issuerCertificateToken {@link CertificateToken} of the issuer
     * @param keys                   a collection of {@link String} keys that can be used as unique identifications of the revocation entry
     * @return {@link RevocationToken}
     */
    private RevocationToken<R> extractAndInsertRevocationTokenFromProxiedSource(
            final CertificateToken certificateToken, final CertificateToken issuerCertificateToken,
            final Collection<String> keys) {
        if (proxiedSource == null) {
            LOG.warn("Proxied revocation source is not initialized for the called RevocationSource!");
            return null;
        }


        RevocationToken<R> revocationToken =
                proxiedSource.getRevocationToken(certificateToken, issuerCertificateToken);
        if (revocationToken != null) {
            if (revocationToken.isValid()) {
                String sourceUrl = getRevocationSourceUrl(certificateToken, revocationToken);
                if (sourceUrl == null) {
                    LOG.warn("Not able to find revocation source URL for certificate '{}'. Revocation will not be added to the cache", certificateToken.getDSSIdAsString());
                    return revocationToken;
                }
                String revocationTokenKey = getRevocationTokenKey(certificateToken, sourceUrl);
                if (!keys.contains(revocationTokenKey)) {
                    insertRevocation(revocationTokenKey, revocationToken);
                    LOG.info("Revocation token for certificate '{}' is added into the cache", certificateToken.getDSSIdAsString());
                } else {
                    updateRevocation(revocationTokenKey, revocationToken);
                    LOG.info("Revocation token for certificate '{}' is updated in the cache", certificateToken.getDSSIdAsString());
                }
            } else {
                LOG.warn("The extracted revocation token with Id '{}' is invalid! Reason: {}",
                        revocationToken.getDSSIdAsString(), revocationToken.getInvalidityReason());
            }
        }
        return revocationToken;
    }

    /**
     * Returns a revocation URL for the given {@code revocationToken}
     *
     * @param certificateToken {@link CertificateToken}
     * @param revocationToken {@link  RevocationToken}
     * @return {@link String}
     */
    protected abstract String getRevocationSourceUrl(CertificateToken certificateToken, RevocationToken<R> revocationToken);

    /**
     * Gets a unique revocation token identifier used to store the revocation token
     * for this {@code certificateToken} within a repository
     *
     * @param certificateToken {@link CertificateToken}
     * @param urlString        {@link String} representing a URL used to download the revocation token from
     * @return {@link String} revocation token key
     */
    protected abstract String getRevocationTokenKey(CertificateToken certificateToken, String urlString);

    /**
     * Checks if the nextUpdate date is currently valid with respect of
     * nextUpdateDelay and maxNexUpdateDelay parameters.
     *
     * @param revocationToken        {@code CRLToken} or {@code OCSPToken}
     * @param certificateTokenIssuer issuer of a CertificateToken to check the revocation for
     * @return TRUE if the token is still valid, FALSE otherwise
     */
    private boolean isNotExpired(RevocationToken<R> revocationToken, CertificateToken certificateTokenIssuer) {
        Date validationDate = new Date();

        Date nextUpdate = revocationToken.getNextUpdate();
        if (nextUpdate == null) {
            // check the validity of the issuer certificate
            CertificateToken revocationIssuer = revocationToken.getIssuerCertificateToken();
            if (revocationIssuer == null) {
                revocationIssuer = certificateTokenIssuer;
            }
            if (!revocationIssuer.isValidOn(validationDate)) {
                return false;
            }
        }

        // check the validity of the revocation token itself
        final Date thisUpdate = revocationToken.getThisUpdate();
        if (nextUpdate == null && defaultNextUpdateDelay != null && thisUpdate != null) {
            nextUpdate = new Date(thisUpdate.getTime() + defaultNextUpdateDelay);
        }
        if (nextUpdate != null) {
            if (maxNextUpdateDelay != null && thisUpdate != null) {
                Date maxNextUpdate = new Date(thisUpdate.getTime() + maxNextUpdateDelay);
                if (nextUpdate.after(maxNextUpdate)) {
                    nextUpdate = maxNextUpdate;
                }
            }
            return nextUpdate.after(validationDate);
        }

        return false;
    }

}
