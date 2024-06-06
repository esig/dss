package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.function.Predicate;

/**
 * This class implements a document loading logic, defined within ETSI TS 119 612 "6.1 TL publication"
 * for Trusted Lists.
 * The class will try to access a corresponding .sha2 file for every requested document available in the cache,
 * compare its digest, and will enforce a document update if the document has expired.
 * The class provides constructors allowing manual configuration of the object, as well as static methods
 * allowing to instantiate pre-configured objects for Trusted Lists validation. See:
 * - {@code #initSha2StrictDataLoader} method to create a dataloader, enforcing refresh of a Trusted List
 *                 only when a new .sha2 document is obtained or NextUpdate has been reached;
 * - {@code #initSha2DailyUpdateDataLoader} method to create a dataloader, enforcing refresh of a Trusted List
 *                 when a new .sha2 document is obtained, NextUpdate has been reached or when the document
 *                 has not been updated for at least 24 hours;
 * - {@code #initSha2CustomExpirationDataLoader} method to create a dataloader, enforcing refresh of a Trusted List
 *                 when a new .sha2 document is obtained, NextUpdate has been reached or when the document
 *                 has not been updated for the indicated time period;
 * - {@code #initSha2IgnoredDataLoader} method to create a dataloader, enforcing refresh of a Trusted List
 *                 in all cases.
 *
 */
public class Sha2FileCacheDataLoader implements DSSCacheFileLoader {

    private static final long serialVersionUID = 3104647343425527021L;

    private static final Logger LOG = LoggerFactory.getLogger(Sha2FileCacheDataLoader.class);

    /**
     * File cache data loader used to load the document
     */
    private DSSCacheFileLoader dataLoader;

    /**
     * This predicate is used to check whether the sha2 document matched the digest of the original document or
     * refresh of the document shall be enforced
     */
    private Predicate<DocumentWithSha2> predicate;

    /**
     * Creates an object with an empty configuration (shall be provided with a setter)
     */
    public Sha2FileCacheDataLoader() {
        // empty
    }

    /**
     * Creates an object with a defined {@code DSSCacheFileLoader}.
     * The {@code predicate} shall be provided with a setter.
     *
     * @param dataLoader {@link DSSCacheFileLoader} to use
     */
    public Sha2FileCacheDataLoader(DSSCacheFileLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    /**
     * This method instantiates a Sha2FileCacheDataLoader with a pre-configured predicate, forcing a Trusted List
     * refresh in case of an updated .sha2 document, or when a NextUpdate has been reached.
     * The created object does not enforce refresh after a specific time period.
     *
     * @param dataLoader {@link DSSCacheFileLoader} to be used to load the document
     * @return {@link Sha2FileCacheDataLoader}
     */
    public static Sha2FileCacheDataLoader initSha2StrictDataLoader(DSSCacheFileLoader dataLoader) {
        Sha2FileCacheDataLoader sha2DataLoader = new Sha2FileCacheDataLoader(dataLoader);

        DefaultTrustedListWithSha2Predicate sha2Predicate = new DefaultTrustedListWithSha2Predicate();
        sha2Predicate.setCacheExpirationTime(-1); // cache do not expire
        sha2DataLoader.setPredicate(sha2Predicate);

        return sha2DataLoader;
    }

    /**
     * This method instantiates a Sha2FileCacheDataLoader with a pre-configured predicate, forcing a Trusted List
     * refresh in case of an updated .sha2 document, when a NextUpdate has been reached,
     * or when the document has not been re-downloaded for at least a day.
     *
     * @param dataLoader {@link DSSCacheFileLoader} to be used to load the document
     * @return {@link Sha2FileCacheDataLoader}
     */
    public static Sha2FileCacheDataLoader initSha2DailyUpdateDataLoader(DSSCacheFileLoader dataLoader) {
        Sha2FileCacheDataLoader sha2DataLoader = new Sha2FileCacheDataLoader(dataLoader);

        DefaultTrustedListWithSha2Predicate sha2Predicate = new DefaultTrustedListWithSha2Predicate();
        sha2Predicate.setCacheExpirationTime(24 * 60 * 60 * 1000); // 24 hours
        sha2DataLoader.setPredicate(sha2Predicate);

        return sha2DataLoader;
    }

    /**
     * This method instantiates a Sha2FileCacheDataLoader with a pre-configured predicate, forcing a Trusted List
     * refresh in case of an updated .sha2 document, when a NextUpdate has been reached,
     * or when the cached document expired according to the provided {@code cacheExpirationTime} value.
     *
     * @param dataLoader {@link DSSCacheFileLoader} to be used to load the document
     * @param cacheExpirationTime value in milliseconds indicating a maximum time after which a document shall be re-downloaded
     * @return {@link Sha2FileCacheDataLoader}
     */
    public static Sha2FileCacheDataLoader initSha2CustomExpirationDataLoader(DSSCacheFileLoader dataLoader, long cacheExpirationTime) {
        Sha2FileCacheDataLoader sha2DataLoader = new Sha2FileCacheDataLoader(dataLoader);

        DefaultTrustedListWithSha2Predicate sha2Predicate = new DefaultTrustedListWithSha2Predicate();
        sha2Predicate.setCacheExpirationTime(cacheExpirationTime);
        sha2DataLoader.setPredicate(sha2Predicate);

        return sha2DataLoader;
    }

    /**
     * This method instantiates a Sha2FileCacheDataLoader with a pre-configured predicate, forcing a Trusted List
     * refresh in all cases despite the .sha2 file document content.
     *
     * @param dataLoader {@link DSSCacheFileLoader} to be used to load the document
     * @return {@link Sha2FileCacheDataLoader}
     */
    public static Sha2FileCacheDataLoader initSha2IgnoredDataLoader(DSSCacheFileLoader dataLoader) {
        Sha2FileCacheDataLoader sha2DataLoader = new Sha2FileCacheDataLoader(dataLoader);

        DefaultTrustedListWithSha2Predicate sha2Predicate = new DefaultTrustedListWithSha2Predicate();
        sha2Predicate.setCacheExpirationTime(0); // cache is always updated
        sha2DataLoader.setPredicate(sha2Predicate);

        return sha2DataLoader;
    }

    /**
     * Sets the file cache data loader to be used to load the
     *
     * @param dataLoader {@link DSSCacheFileLoader}
     */
    public void setDataLoader(DSSCacheFileLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    /**
     * This method sets a predicate evaluating a condition for a document to be refreshed.
     * The predicate returns TRUE when the condition is valid and no document refresh is required, FALSE otherwise
     *
     * @param predicate {@link Predicate}
     */
    public void setPredicate(Predicate<DocumentWithSha2> predicate) {
        this.predicate = predicate;
    }

    @Override
    public DSSDocument getDocument(String url) throws DSSException {
        return getDocument(url, false);
    }

    @Override
    public DSSDocument getDocument(String url, boolean refresh) {
        assertConfigurationIsValid();

        DSSDocument sha2Document = null;
        String sha2ExtractionStatus = null;
        try {
            sha2Document = getSha2File(url);
        } catch (Exception e) {
            sha2ExtractionStatus = e.getMessage();
            String errorMessage = String.format("No sha2 document has been found : %s", sha2ExtractionStatus);
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e);
            } else {
                LOG.warn(errorMessage);
            }
            refresh = true; // force the refresh
        }

        DSSDocument cachedDocument = null;
        DSSDocument refreshedDocument = null;
        if (refresh) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Refresh has been requested for a document with URL '{}'", url);
            }
            refreshedDocument = getRefreshedDocument(url);

        } else {
            cachedDocument = getDocumentFromCache(url);
            if (cachedDocument == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No cached document found for URL '{}'", url);
                }
                refreshedDocument = getRefreshedDocument(url);
            }
        }

        DocumentWithSha2 documentWithSha2 = null;
        if (cachedDocument != null) {
            documentWithSha2 = mergeDocumentWithSha2(cachedDocument, sha2Document);
            if (checkRefreshRequired(documentWithSha2)) {
                LOG.info("Refresh the document from URL '{}'...", url);
                refreshedDocument = getRefreshedDocument(url);

            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Sha2 document condition match. Return cached document for URL '{}'", url);
                }
            }
        }

        if (refreshedDocument != null) {
            documentWithSha2 = mergeDocumentWithSha2(refreshedDocument, sha2Document);
            checkRefreshRequired(documentWithSha2); // verify if new document matches sha2
        }

        if (documentWithSha2 != null && Utils.isStringNotEmpty(sha2ExtractionStatus)) {
            documentWithSha2.addErrorMessage(sha2ExtractionStatus);
        }

        return documentWithSha2;
    }

    /**
     * This method returns a document from cache, when applicable.
     * If no document is available in the cache, returns NULL.
     *
     * @param documentUrl {@link String} representing document's access point
     * @return {@link DSSDocument}
     */
    protected DSSDocument getRefreshedDocument(String documentUrl) {
        try {
            return dataLoader.getDocument(documentUrl, true);
        } catch (Exception e) {
            String errorMessage = "An error occurred on document extraction from URL '{}' : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, documentUrl, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, documentUrl, e.getMessage());
            }
            return null;
        }
    }

    /**
     * This method returns a sha2 file for the given {@code documentUrl}. If not sha2 document found, returns NULL.
     *
     * @param documentUrl {@link String} URL of the document, for which to retrieve a sha2 file
     * @return {@link DSSDocument} representing a sha2 file
     */
    protected DSSDocument getSha2File(String documentUrl) {
        String sha2FileUrl = getSha2FileUrl(documentUrl);
        return dataLoader.getDocument(sha2FileUrl, true);
    }

    /**
     * Method transforms a given {@code documentUrl} to a corresponding URL location containing a sha2 document
     *
     * @param documentUrl {@link String} URL of the document to be retrieved
     * @return {@link String} URL of the sha2 corresponding to the document to be retrieved
     */
    protected String getSha2FileUrl(String documentUrl) {
        // "." is ignored in processing, to allow processing for some exotic cases
        String fileExtension = Utils.getFileNameExtension(documentUrl);
        if (fileExtension != null && !fileExtension.isEmpty() && documentUrl.length() > fileExtension.length()) {
            fileExtension = documentUrl.substring(documentUrl.length() - 1 - fileExtension.length()); // add dot
            documentUrl = documentUrl.substring(0, documentUrl.length() - fileExtension.length()); // remove extension
        }
        assertExtensionIsSupported(fileExtension);
        return documentUrl + ".sha2";
    }

    /**
     * This method verifies whether the remote document's {@code fileExtension} is supported by the implementation.
     * The Trusted Lists distribution points shall end with ".xml" or ".xtsl" strings
     *
     * @param fileExtension {@link String} to check
     */
    protected void assertExtensionIsSupported(String fileExtension) {
        if (!".xml".equals(fileExtension) && !".xtsl".equals(fileExtension)) {
            throw new DSSExternalResourceException(String.format("The Trusted List extension '%s' is not supported! " +
                    "Shall be one of '.xml' or '.xtsl'.", fileExtension));
        }
    }

    /**
     * This class creates a {@code eu.europa.esig.dss.tsl.sha2.DocumentWithSha2} object by merging
     * a {@code cachedDocument} and {@code sha2Document} together
     *
     * @param cachedDocument {@link DSSDocument} representing an original cached document
     * @param sha2Document {@link DSSDocument} representing a sha2 document
     * @return {@link DocumentWithSha2}
     */
    protected DocumentWithSha2 mergeDocumentWithSha2(DSSDocument cachedDocument, DSSDocument sha2Document) {
        return new DocumentWithSha2(cachedDocument, sha2Document);
    }

    /**
     * This method checks whether the cached document should be refreshed
     *
     * @param documentWithSha2 {@link DocumentWithSha2} representing the original document with sha2 file content
     * @return TRUE if the document shall be refreshed, FALSE otherwise
     */
    protected boolean checkRefreshRequired(DocumentWithSha2 documentWithSha2) {
        return !predicate.test(documentWithSha2);
    }

    @Override
    public DSSDocument getDocumentFromCache(String url) {
        assertConfigurationIsValid();
        try {
            return dataLoader.getDocumentFromCache(url);
        } catch (Exception e) {
            String errorMessage = "An error occurred on cached document extraction from URL '{}' : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, url, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, url, e.getMessage());
            }
            return null;
        }
    }

    @Override
    public boolean remove(String url) {
        assertConfigurationIsValid();
        return dataLoader.remove(url);
    }

    /**
     * This method verifies whether the configuration of the class is complete to proceed with execution
     */
    protected void assertConfigurationIsValid() {
        Objects.requireNonNull(dataLoader, "DSSCacheFileLoader shall be provided!");
        Objects.requireNonNull(predicate, "Predicate shall be provided!");
    }

}
