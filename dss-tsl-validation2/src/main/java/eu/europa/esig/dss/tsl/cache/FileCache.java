package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.cache.result.FileResult;

/**
 * The FileCache to store files
 *
 */
public class FileCache extends AbstractCache<FileResult> {

	private static final Logger LOG = LoggerFactory.getLogger(FileCache.class);
	
	/**
	 * Returns the file for the provided {@code cacheKey}
	 * @param cacheKey {@link String} of the file
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getFile(String cacheKey) {
		LOG.trace("Extracting the file for key [{}]...", cacheKey);
		FileResult cachedResult = getCachedResult(cacheKey);
		if (cachedResult != null) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Returning the file for key [{}] with digest [{}]", cacheKey, cachedResult.getBase64Digest());
			}
			return cachedResult.getFile();
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns digest for the file with the provided key
	 * @param cacheKey {@link String} key of the file to get digest for
	 * @return {@link String} base64 digest of the requested file
	 */
	public String getFileDigest(String cacheKey) {
		LOG.trace("Extracting digest of file for the key [{}]...", cacheKey);
		FileResult cachedResult = getCachedResult(cacheKey);
		if (cachedResult != null) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Returning digest of file for key [{}] with value [{}]", cacheKey, cachedResult.getBase64Digest());
			}
			return cachedResult.getBase64Digest();
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Checks if the file with the given {@code cacheKey} is up to date
	 * @param cacheKey {@link String} cached file key
	 * @param base64Digest {@link String} digest of the new loaded file to compare
	 * @return TRUE if digests match (file is up to date), FALSE otherwise
	 */
	public boolean isUpToDate(String cacheKey, String base64Digest) {
		LOG.trace("Extracting cached file for the key [{}]...", cacheKey);
		FileResult cachedResult = getCachedResult(cacheKey);
		if (cachedResult != null) {
			LOG.trace("Comparing digest of the store file [{}] with the loaded file [{}]", cachedResult.getBase64Digest(), base64Digest);
			boolean upToDate = base64Digest.equals(cachedResult.getBase64Digest());
			LOG.trace("Does file with key [{}] is up to date ? {}", upToDate);
			return upToDate;
		}
		LOG.trace("The FileCache does not contain a file result for the key [{}]!", cacheKey);
		return false;
	}

}
