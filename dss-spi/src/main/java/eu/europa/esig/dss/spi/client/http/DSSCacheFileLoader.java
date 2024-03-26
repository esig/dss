package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class implements a file loader implementing a caching mechanism, allowing to remove
 * cache externally (to be used within a {@code CacheCleaner})
 *
 */
public interface DSSCacheFileLoader extends DSSFileLoader {

    /**
     * This method allows to download a {@code DSSDocument} from a specified {@code url} with a custom setting
     * indicating whether the {@code refresh} of the document's cache shall be enforced, when applicable
     *
     * @param url {@link String} remote location of the document to download
     * @param refresh indicates whether the refresh of the cached document shall be enforced
     * @return {@link DSSDocument}
     */
    DSSDocument getDocument(final String url, final boolean refresh);

    /**
     * Allows to load a document for a given url from the cache folder.
     * If the document is not found in the cache, returns NULL.
     *
     * @param url {@link String} url of the file
     * @return {@link DSSDocument} or NULL if the file does not exist
     */
    DSSDocument getDocumentFromCache(final String url);

    /**
     * Removes the file from cache with the given url
     *
     * @param url {@link String} url of the remote file location (the same what was used on file saving)
     * @return TRUE when file was successfully deleted, FALSE otherwise
     */
    boolean remove(final String url);

}
