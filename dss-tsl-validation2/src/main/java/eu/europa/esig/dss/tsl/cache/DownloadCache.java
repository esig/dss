package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;

/**
 * The DownloadCache to store files
 *
 */
public class DownloadCache extends AbstractCache<XmlDownloadResult> {

	private static final Logger LOG = LoggerFactory.getLogger(DownloadCache.class);
	
	/**
	 * Returns the file for the provided {@code cacheKey}
	 * @param cacheKey {@link CacheKey} of the file
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getFile(CacheKey cacheKey) {
		LOG.trace("Extracting the file for key [{}]...", cacheKey);
		CachedEntry<XmlDownloadResult> cachedFileEntry = get(cacheKey);
		if (cachedFileEntry != null && !cachedFileEntry.isEmpty()) {
			XmlDownloadResult downloadResult = cachedFileEntry.getCachedObject();
			if (LOG.isTraceEnabled()) {
				LOG.trace("Returning the file for key [{}] with digest [{}]", cacheKey, downloadResult.getDigest());
			}
			return downloadResult.getDSSDocument();
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns digest for the file with the provided key
	 * @param cacheKey {@link CacheKey} of the file to get digest for
	 * @return {@link Digest} of the requested file
	 */
	public Digest getFileDigest(CacheKey cacheKey) {
		LOG.trace("Extracting digest of file for the key [{}]...", cacheKey);
		CachedEntry<XmlDownloadResult> cachedFileEntry = get(cacheKey);
		if (cachedFileEntry != null && !cachedFileEntry.isEmpty()) {
			XmlDownloadResult downloadResult = cachedFileEntry.getCachedObject();
			if (LOG.isTraceEnabled()) {
				LOG.trace("Returning digest of file for key [{}] with value [{}]", cacheKey, downloadResult.getDigest());
			}
			return downloadResult.getDigest();
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Checks if the file with the given {@code cacheKey} is up to date
	 * @param cacheKey {@link CacheKey}
	 * @param xmlDownloadResult {@link XmlDownloadResult} value to compare with
	 * @return TRUE if digests match (file is up to date), FALSE otherwise
	 */
	public boolean isUpToDate(CacheKey cacheKey, XmlDownloadResult xmlDownloadResult) {
		LOG.trace("Extracting cached file for the key [{}]...", cacheKey);
		CachedEntry<XmlDownloadResult> cachedFileEntry = get(cacheKey);
		if (cachedFileEntry != null && !cachedFileEntry.isEmpty()) {
			XmlDownloadResult downloadResult = cachedFileEntry.getCachedObject();
			LOG.trace("Comparing digest of the stored file [{}] with the downloaded file [{}]", downloadResult.getDigest(), xmlDownloadResult.getDigest());
			boolean upToDate = downloadResult.getDigest().equals(xmlDownloadResult.getDigest());
			LOG.trace("Does file with key [{}] is up to date ? {}", upToDate);
			return upToDate;
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return false;
	}

	@Override
	protected CacheType getCacheType() {
		return CacheType.DOWNLOAD;
	}

}
