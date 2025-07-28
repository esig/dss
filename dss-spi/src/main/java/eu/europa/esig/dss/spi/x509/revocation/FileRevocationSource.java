package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.DSSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Abstract class that extends {@code RepositoryRevocationSource} to provide
 * file-based caching functionality for revocation data.
 *
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class FileRevocationSource<R extends Revocation> extends RepositoryRevocationSource<R> {

	private static final Logger LOG = LoggerFactory.getLogger(FileRevocationSource.class);

	private static final long serialVersionUID = 1L;

	/**
	 * The directory where cached revocation files are stored
	 */
	private final File cacheDirectory;

	/**
	 * Constructor that initializes the file revocation source with a cache
	 * directory.
	 *
	 * @param cacheDirectoryPath the path to the directory where cached files will
	 *                           be stored
	 */
	protected FileRevocationSource(String cacheDirectoryPath) {
		Objects.requireNonNull(cacheDirectoryPath, "Cache directory path cannot be null");
		this.cacheDirectory = new File(cacheDirectoryPath);
		initializeCacheDirectory();
	}

	/**
	 * Constructor that initializes the file revocation source with a cache
	 * directory.
	 *
	 * @param cacheDirectory the directory where cached files will be stored
	 */
	protected FileRevocationSource(File cacheDirectory) {
		Objects.requireNonNull(cacheDirectory, "Cache directory cannot be null");
		this.cacheDirectory = cacheDirectory;
		initializeCacheDirectory();
	}

	/**
	 * Initializes the cache directory by creating it if it doesn't exist
	 */
	private void initializeCacheDirectory() {
		if (!cacheDirectory.exists()) {
			if (cacheDirectory.mkdirs()) {
				LOG.info("Cache directory '{}' created successfully", cacheDirectory.getAbsolutePath());
			} else {
				throw new IllegalStateException(
						String.format("Unable to create cache directory '%s'", cacheDirectory.getAbsolutePath()));
			}
		}
		if (!cacheDirectory.isDirectory()) {
			throw new IllegalArgumentException(
					String.format("Cache path '%s' is not a directory", cacheDirectory.getAbsolutePath()));
		}
	}

	/**
	 * Gets the cache directory
	 *
	 * @return the cache directory
	 */
	public FileDocument getCacheDirectory() {
		return new FileDocument(cacheDirectory);
	}

	@Override
	protected List<RevocationToken<R>> findRevocations(String key, CertificateToken certificateToken,
	                                                   CertificateToken issuerCertToken) {
		List<RevocationToken<R>> revocationTokens = new ArrayList<>();

		File cacheFile = getCacheFileFromKey(key);
		if (!cacheFile.exists()) {
			return revocationTokens;
		}

		try {
			byte[] cachedData = Files.readAllBytes(cacheFile.toPath());
			if (cachedData.length == 0) {
				return revocationTokens;
			}

			RevocationToken<R> token = reconstructTokenFromEncodedData(cachedData, certificateToken, issuerCertToken);

			if (token == null) {
				LOG.warn("Failed to reconstruct revocation token from cache for key: {}", key);
				deleteCacheFile(cacheFile);
				return revocationTokens;
			}

			if (!isNotExpired(token, issuerCertToken)) {
				LOG.debug("Cached revocation token expired for key: {}", key);
				deleteCacheFile(cacheFile);
				return revocationTokens;
			}

			revocationTokens.add(token);
		} catch (Exception e) {
			LOG.warn("Failed to read cache file for key '{}': {}", key, e.getMessage());
			// If we can't read the file, delete it
			deleteCacheFile(cacheFile);
		}

		return revocationTokens;
	}

	@Override
	protected void insertRevocation(String revocationKey, RevocationToken<R> token) {
		File cacheFile = getCacheFileFromKey(revocationKey);
		byte[] encodedData = token.getEncoded();

		DSSUtils.saveToFile(encodedData, cacheFile);

		LOG.debug("Revocation token inserted into cache file for key: {}", revocationKey);
	}

	@Override
	protected void updateRevocation(String revocationKey, RevocationToken<R> token) {
		// For file-based cache, update is the same as insert (replace the file content)
		insertRevocation(revocationKey, token);
		LOG.debug("Revocation token updated in cache file for key: {}", revocationKey);
	}

	@Override
	protected void removeRevocation(String revocationKey) {
		File cacheFile = getCacheFileFromKey(revocationKey);

		if (!cacheFile.exists()) {
			return;
		}

		deleteCacheFile(cacheFile);
		LOG.debug("Revocation token removed from cache for key: {}", revocationKey);
	}

	/**
	 * Creates a revocation token from cached encoded data
	 *
	 * @param encodedData      the cached encoded revocation data
	 * @param certificateToken the certificate token
	 * @param issuerCertToken  the issuer certificate token
	 * @return the revocation token or null if creation fails
	 */
	protected abstract RevocationToken<R> reconstructTokenFromEncodedData(byte[] encodedData,
	                                                                      CertificateToken certificateToken,
	                                                                      CertificateToken issuerCertToken);

	/**
	 * Gets the file extension used for cached revocation files.
	 *
	 * @return the file extension (e.g., ".crl" or ".ocsp")
	 */
	protected abstract String getFileExtension();

	/**
	 * Gets the cache file for a given key
	 *
	 * @param key the cache key
	 * @return the cache file
	 */
	protected File getCacheFileFromKey(String key) {
		return new File(cacheDirectory, key + getFileExtension());
	}

	/**
	 * Deletes a cache file
	 *
	 * @param cacheFile the file to delete
	 */
	protected void deleteCacheFile(File cacheFile) {
		try {
			Files.deleteIfExists(cacheFile.toPath());
		} catch (IOException e) {
			LOG.warn("Failed to delete cache file '{}': {}", cacheFile.getAbsolutePath(), e.getMessage());
		}
	}

	/**
	 * Clears all cached files from the cache directory
	 */
	public void clearCache() {
		if (!cacheDirectory.exists()) {
			return;
		}

		if (!cacheDirectory.isDirectory()) {
			LOG.warn("Cache directory '{}' is not a directory", cacheDirectory.getAbsolutePath());
			return;
		}

		File[] files = cacheDirectory.listFiles();
		if (files != null) {
			for (File file : files) {
				if (file.isFile() && file.getName().endsWith(getFileExtension())) {
					deleteCacheFile(file);
				}
			}
		}

		LOG.info("Cache cleared for directory: {}", cacheDirectory.getAbsolutePath());
	}

}
