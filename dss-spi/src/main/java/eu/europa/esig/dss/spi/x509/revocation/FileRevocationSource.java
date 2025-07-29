package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Abstract class that extends {@code RepositoryRevocationSource} to provide
 * file-based caching functionality for revocation data.
 *
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class FileRevocationSource<R extends Revocation> extends RepositoryRevocationSource<R> {

	private static final long serialVersionUID = 988823509470487135L;

	private static final Logger LOG = LoggerFactory.getLogger(FileRevocationSource.class);

	/**
	 * The directory where cached revocation files are stored
	 * Default : Temporary directory with a "/dss-cache-revocation" subdirectory
	 */
	private File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir"), "/dss-cache-revocation");

	/**
	 * Empty constructor.
	 * The proxied revocation source can be provided using the {@code #setProxySource} method.
	 */
	protected FileRevocationSource() {
		// empty
	}

	/**
	 * Constructor that initializes the file revocation source with a proxied revocation source provided.
	 *
	 * @param proxiedSource {@link RevocationSource} to be used to load revocation data when the corresponding
	 *                                               revocation document is not available in the file system.
	 */
	protected FileRevocationSource(RevocationSource<R> proxiedSource) {
		this.proxiedSource = proxiedSource;
	}

	/**
	 * This method allows to set the file cache directory. If the cache folder does not exist then it's created.
	 * Default : Temporary directory with a "/dss-cache-revocation" subdirectory
	 *
	 * @param fileCacheDirectory
	 *            {@code File} pointing the cache folder to be used.
	 */
	public void setFileCacheDirectory(File fileCacheDirectory) {
		Objects.requireNonNull(fileCacheDirectory, "File cache directory cannot be null!");
		this.fileCacheDirectory = initializeCacheDirectory(fileCacheDirectory);;
	}

	/**
	 * Initializes the cache directory by creating it if it doesn't exist
	 *
	 * @param fileCacheDirectory {@link File} directory to be initialized if not present
	 * @return {@link File} initialized {@code File} directory
	 */
	private File initializeCacheDirectory(File fileCacheDirectory) {
		if (!fileCacheDirectory.exists()) {
			if (fileCacheDirectory.mkdirs()) {
				LOG.info("Cache directory '{}' created successfully", fileCacheDirectory.getAbsolutePath());
			} else {
				throw new IllegalStateException(
						String.format("Unable to create cache directory '%s'", fileCacheDirectory.getAbsolutePath()));
			}
		}
		if (!fileCacheDirectory.isDirectory()) {
			throw new IllegalArgumentException(
					String.format("Cache path '%s' is not a directory", fileCacheDirectory.getAbsolutePath()));
		}
		return fileCacheDirectory;
	}

	/**
	 * Gets the cache directory
	 *
	 * @return {@link File} the cache directory
	 */
	public File getFileCacheDirectory() {
		return fileCacheDirectory;
	}

	@Override
	protected List<RevocationToken<R>> findRevocations(String key, CertificateToken certificateToken,
	                                                   CertificateToken issuerCertToken) {
		FileCacheEntry revocationCache = getRevocationCache(key);
		if (revocationCache.exists()) {
			try {
				RevocationToken<R> token = reconstructTokenFromEncodedData(revocationCache, certificateToken, issuerCertToken);
				if (token != null) {
					return Collections.singletonList(token);
				}
				LOG.warn("Failed to reconstruct revocation token from cache for key: {}", key);

			} catch (Exception e) {
				LOG.warn("Failed to read revocation cache file for key '{}': {}", key, e.getMessage(), e);
			}
		}
		return Collections.emptyList();
	}

	private FileCacheEntry getRevocationCache(String key) {
		return new FileCacheEntry(key, getRevocationFileExtension());
	}

	@Override
	protected void insertRevocation(String revocationKey, RevocationToken<R> token) {
		FileCacheEntry revocationCache = getRevocationCache(revocationKey);
		saveRevocationToken(revocationCache, token);
		LOG.debug("Revocation token inserted into cache file for key: {}", revocationKey);
	}

	/**
	 * Writes the {@code revocationToken} within the file system
	 *
	 * @param revocationCache {@link FileCacheEntry}
	 * @param token {@link RevocationToken} to store
	 */
	protected void saveRevocationToken(FileCacheEntry revocationCache, RevocationToken<R> token) {
		revocationCache.saveRevocationToken(token);
	}

	@Override
	protected void updateRevocation(String revocationKey, RevocationToken<R> token) {
		// For file-based cache, update is the same as insert (replace the file content)
		insertRevocation(revocationKey, token);
		LOG.debug("Revocation token updated in cache file for key: {}", revocationKey);
	}

	@Override
	protected void removeRevocation(String revocationKey) {
		FileCacheEntry revocationCache = getRevocationCache(revocationKey);
		if (revocationCache.exists()) {
			if (revocationCache.clean()) {
				LOG.debug("Revocation token and all associated data have been successfully removed from cache for key: {}", revocationKey);
			} else {
				LOG.debug("Some or none files associated with the revocation data have been removed for key: {}", revocationKey);
			}
		}
	}

	/**
	 * Creates a revocation token from cached encoded data
	 *
	 * @param revocationCache  {@link FileCacheEntry} the cached revocation data entry
	 * @param certificateToken {@link CertificateToken} the certificate token
	 * @param issuerCertToken  {@link CertificateToken} the issuer certificate token
	 * @return the revocation token or null if creation fails
	 */
	protected abstract RevocationToken<R> reconstructTokenFromEncodedData(FileCacheEntry revocationCache,
	                                                                      CertificateToken certificateToken,
	                                                                      CertificateToken issuerCertToken);

	/**
	 * Gets the file extension used for cached revocation files.
	 *
	 * @return the file extension (e.g., ".crl" or ".ocsp")
	 */
	protected abstract String getRevocationFileExtension();

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
		if (!fileCacheDirectory.exists()) {
			LOG.warn("Cache directory '{}' does not exist!", fileCacheDirectory.getAbsolutePath());
			return;
		}

		if (!fileCacheDirectory.isDirectory()) {
			LOG.warn("Cache directory '{}' is not a directory", fileCacheDirectory.getAbsolutePath());
			return;
		}

		try {
			Utils.cleanDirectory(fileCacheDirectory);
			LOG.info("Cache cleared for directory: {}", fileCacheDirectory.getAbsolutePath());

		} catch (IOException e) {
			LOG.warn("Failed to clean the directory '{}' : {}", fileCacheDirectory.getAbsolutePath(), e.getMessage(), e);
		}
	}

	/**
	 * This class represents a cache entry related to a single revocation token
	 */
	protected class FileCacheEntry {

		/** File extension used to store a revocation data issuer certificate */
		private static final String CERT_FILE_EXTENSION = ".cer";

		/** File extension used to define the original revocation data URI */
		private static final String URI_FILE_EXTENSION = ".uri";

		/** The key associated with a revocation token */
		private final String key;

		/** The extension used for the revocation data filename definition */
		private final  String revocationExtension;

		/**
		 * Default constructor
		 *
		 * @param key {@link String} unique identifier of the revocation data (e.g. a normalized URI location)
		 * @param revocationExtension {@link String} filename extension for the revocation data document
		 */
		public FileCacheEntry(final String key, final String revocationExtension) {
			this.key = key;
			this.revocationExtension = revocationExtension;
		}

		/**
		 * Gets the revocation data binaries, when present
		 *
		 * @return byte array
		 */
		public byte[] getRevocationDataBinaries() {
			File cacheFile = getCacheRevocationFile();
			return getFileContent(cacheFile);
		}

		/**
		 * Gets URL originally used to retrieve the revocation data
		 *
		 * @return {@link String}
		 */
		public String getRevocationDataSourceUrl() {
			File cacheUriFile = getCacheUriFile();
			byte[] fileContent = getFileContent(cacheUriFile);
			if (fileContent != null) {
				return new String(fileContent, StandardCharsets.UTF_8);
			}
			return null;
		}

		/**
		 * Gets a revocation data issuer's certificate, when present in the filesystem
		 *
		 * @return {@link CertificateToken}
		 */
		public CertificateToken getIssuerCertificateToken() {
			File issuerCertificateFile = getCacheRevocationIssuerCertificateFile();
			if (issuerCertificateFile.exists()) {
				try {
					byte[] encodedCertificate = getFileContent(issuerCertificateFile);
					return DSSUtils.loadCertificate(encodedCertificate);
				} catch (Exception e) {
					LOG.warn("Unable to load revocation data issuer certificate from file with filename '{}' : {}",
							issuerCertificateFile.getName(), e.getMessage(), e);
				}
			}
			return null;
		}

		private byte[] getFileContent(File file) {
			try {
				if (file.exists()) {
					return DSSUtils.toByteArray(file);
				} else {
					LOG.warn("The file '{}' does not exist or has been removed.", file.getName());
				}
			} catch (Exception e) {
				LOG.warn("Failed to read revocation cache file for key '{}': {}", key, e.getMessage());
			}
			return null;
		}

		/**
		 * Gets the cached revocation file
		 *
		 * @return the cache file
		 */
		private File getCacheRevocationFile() {
			return getCacheFileFromKey(revocationExtension);
		}

		/**
		 * Gets the cached URI file
		 *
		 * @return the cache file
		 */
		private File getCacheUriFile() {
			return getCacheFileFromKey(URI_FILE_EXTENSION);
		}

		/**
		 * Gets the cached revocation data issuer certificate file
		 *
		 * @return the cache file
		 */
		private File getCacheRevocationIssuerCertificateFile() {
			return getCacheFileFromKey(CERT_FILE_EXTENSION);
		}

		/**
		 * Gets the cache file for a given key and target extension
		 *
		 * @param fileExtension {@link String} file extension
		 * @return the cache file
		 */
		private File getCacheFileFromKey(String fileExtension) {
			return new File(fileCacheDirectory, key + fileExtension);
		}

		/**
		 * Writes {@code revocationToken} to corresponding cache document and associated documents
		 *
		 * @param revocationToken {@link RevocationToken}
		 */
		public void saveRevocationToken(RevocationToken<R> revocationToken) {
			Objects.requireNonNull(revocationToken, "RevocationToken cannot be null!");
			DSSUtils.saveToFile(revocationToken.getEncoded(), getCacheRevocationFile());
			if (revocationToken.getSourceURL() != null) {
				DSSUtils.saveToFile(revocationToken.getSourceURL().getBytes(StandardCharsets.UTF_8), getCacheUriFile());
			}
		}

		/**
		 * Writes {@code certificateToken} to corresponding cache document
		 *
		 * @param certificateToken {@link CertificateToken}
		 */
		public void saveCertificateToken(CertificateToken certificateToken) {
			Objects.requireNonNull(certificateToken, "CertificateToken cannot be null!");
			DSSUtils.saveToFile(certificateToken.getEncoded(), getCacheRevocationIssuerCertificateFile());
		}

		/**
		 * Cleans all files within the file system associated with the current cache entry
		 */
		public boolean clean() {
			boolean cacheCleaned = removeFile(getCacheRevocationFile());
			File cacheUriFile = getCacheUriFile();
			if (cacheUriFile.exists()) {
				cacheCleaned ^= removeFile(cacheUriFile);
			}
			File cacheCertificateFile = getCacheRevocationIssuerCertificateFile();
			if (cacheCertificateFile.exists()) {
				cacheCleaned ^= removeFile(cacheCertificateFile);
			}
			return cacheCleaned;
		}

		private boolean removeFile(File fileToRemove) {
			if (fileToRemove.exists()) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Deleting the file with filename '{}'...", fileToRemove.getName());
				}
				try {
					Files.delete(fileToRemove.toPath());
					return true;

				} catch (IOException e) {
					String errorMessage = "Unable to remove the cached file with name '%s'. Reason : %s";
					if (LOG.isDebugEnabled()) {
						LOG.warn(String.format(errorMessage, fileToRemove.getName(), e.getMessage()), e);
					} else {
						LOG.warn(String.format(errorMessage, fileToRemove.getName(), e.getMessage()));
					}
					return false;
				}
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("Unable to remove the file with filename '{}'! The file does not exist.", fileToRemove.getName());
			}
			return false;
		}

		/**
		 * Checks whether the revocation cache exists
		 *
		 * @return TRUE if the cache exists, FALSE otherwise
		 */
		public boolean exists() {
			return getCacheRevocationFile().exists();
		}

	}

}
