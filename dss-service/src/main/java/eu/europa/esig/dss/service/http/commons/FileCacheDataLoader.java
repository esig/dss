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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class provides some caching features to handle the resources. The default cache folder is set to
 * {@code java.io.tmpdir}. The urls of the resources is transformed to the
 * file name by replacing the special characters by {@code _}
 */
public class FileCacheDataLoader implements DataLoader, DSSFileLoader {

	private static final long serialVersionUID = 1028849693098211169L;

	private static final Logger LOG = LoggerFactory.getLogger(FileCacheDataLoader.class);

	/** The error message if the dataloader is not configured */
	private static final String DATA_LOADER_NOT_CONFIGURED = "The DataLoader is not configured";

	/** The directory to cache files */
	private File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir"));

	/** Loads absolute path */
	private ResourceLoader resourceLoader = new ResourceLoader();

	/** List of URIs to be loaded */
	private List<String> toBeLoaded;

	/** List of URIs to be ignored */
	private List<String> toIgnored;

	/** The cache expiration time, after with the document shall be downloaded again */
	private Long cacheExpirationTime;

	/** The dataloader to be used for a remote files access */
	private DataLoader dataLoader;

	/**
	 * Empty constructor
	 */
	public FileCacheDataLoader() {
	}

	/**
	 * Default constructor
	 *
	 * @param dataLoader {@link DataLoader} to use for remote access (e.g. online)
	 */
	public FileCacheDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Gets the dataloader
	 *
	 * @return {@link DataLoader}
	 */
	public DataLoader getDataLoader() {
		return dataLoader;
	}

	/**
	 * Sets the data loader for a remote documents access (e.g. online)
	 *
	 * @param dataLoader {@link DataLoader}
	 */
	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * This method allows to set the file cache directory. If the cache folder does not exists then it's created.
	 *
	 * @param fileCacheDirectory
	 *            {@code File} pointing the cache folder to be used.
	 */
	public void setFileCacheDirectory(final File fileCacheDirectory) {

		this.fileCacheDirectory = fileCacheDirectory;
		this.fileCacheDirectory.mkdirs();
	}

	/**
	 * Sets the expiration time for the cached files in milliseconds.
	 * If more time has passed from the cache file's last modified time, then a fresh copy is downloaded and cached,
	 * otherwise a cached copy is used.
	 *
	 * If the expiration time is not set, then the cache does not expire.
	 *
	 * @param cacheExpirationTimeInMilliseconds value in milliseconds
	 */
	public void setCacheExpirationTime(long cacheExpirationTimeInMilliseconds) {
		this.cacheExpirationTime = cacheExpirationTimeInMilliseconds;
	}

	/**
	 * Sets the ResourceLoader for an absolute path creation
	 *
	 * @param resourceLoader {@link ResourceLoader}
	 */
	public void setResourceLoader(final ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	/**
	 * This methods allows to indicate if the resource must be obtained. If this method has been invoked then only the
	 * provided URL will be processed.
	 *
	 * @param url
	 *            to be processed
	 */
	public void addToBeLoaded(final String url) {

		if (toBeLoaded == null) {

			toBeLoaded = new ArrayList<>();
		}
		if (Utils.isStringNotBlank(url)) {

			toBeLoaded.add(url);
		}
	}

	/**
	 * This methods allows to indicate which resources must be ignored. It is useful in a test environment where some of
	 * fake sources a not available. It prevents to wait for the
	 * timeout.
	 *
	 * @param urlString
	 *            to be ignored. It can be the original URL or the cache file name
	 */
	public void addToBeIgnored(final String urlString) {

		if (toIgnored == null) {

			toIgnored = new ArrayList<>();
		}
		if (Utils.isStringNotBlank(urlString)) {

			final String normalizedFileName = DSSUtils.getNormalizedString(urlString);
			toIgnored.add(normalizedFileName);
		}
	}

	@Override
	public byte[] get(final String url, final boolean refresh) throws DSSException {
		DSSDocument document = getDocument(url, refresh);
		return DSSUtils.toByteArray(document);
	}

	@Override
	public byte[] get(final String url) throws DSSException {
		return get(url, false);
	}
	
	private DSSDocument getDocument(final String url, final boolean refresh) throws DSSException {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);

		// TODO: review
		if ((toBeLoaded != null) && !toBeLoaded.contains(url)) {
			throw new DSSException(String.format("The toBeLoaded list does not contain URL [%s]!", url));
		}
		final String fileName = DSSUtils.getNormalizedString(url);
		final File file = getCacheFile(fileName);
		final boolean fileExists = file.exists();
		final boolean isCacheExpired = isCacheExpired(file);
		
		if (fileExists && !refresh && !isCacheExpired) {
			LOG.debug("Cached file was used");
			return new FileDocument(file);
			
		} else {
			
			if (!fileExists) {
				LOG.debug("There is no cached file!");
			} else {
				LOG.debug("The refresh is forced!");
			}
			
		}
		
		byte[] bytes = null;
		if (!isNetworkProtocol(url)) {
			bytes = getLocalFileContent(url);
			
		} else {
			bytes = dataLoader.get(url);
			
		}
		
		if (Utils.isArrayNotEmpty(bytes)) {
			final File out = createFile(fileName, bytes);
			return new FileDocument(out);
			
		} 
		throw new DSSException(String.format("Cannot retrieve data from url [%s]. Empty content is obtained!", url));
		
	}

	@Override
	public DSSDocument getDocument(String url) {
		return getDocument(url, false);
	}
	
	@Override
	public boolean remove(String url) {
		final String fileName = DSSUtils.getNormalizedString(url);
		final File file = getCacheFile(fileName);
		return file.delete();
	}

	/**
	 * Checks if the URL defines a network protocol
	 *
	 * @param urlString {@link String} url to check
	 * @return TRUE if the URL defines a network protocol, FALSE otherwise
	 */
	protected boolean isNetworkProtocol(final String urlString) {
		final String normalizedUrl = Utils.trim(urlString).toLowerCase();
		return Protocol.isHttpUrl(normalizedUrl) || Protocol.isLdapUrl(normalizedUrl) || Protocol.isFtpUrl(normalizedUrl);
	}

	private byte[] getLocalFileContent(final String urlString) throws DSSException {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);
		// TODO usage ??
		final String resourcePath = resourceLoader.getAbsoluteResourceFolder(Utils.trim(urlString));
		if (resourcePath != null) {
			final File fileResource = new File(resourcePath);
			return DSSUtils.toByteArray(fileResource);
		} else {
			return dataLoader.get(urlString);
		}
	}

	private File getCacheFile(final String fileName) {

		final String trimmedFileName = Utils.trim(fileName);
		if ((toIgnored != null) && toIgnored.contains(trimmedFileName)) {

			throw new DSSException("Part of urls to ignore.");
		}
		LOG.debug("Cached file: {}/{}", fileCacheDirectory, trimmedFileName);
		final File file = new File(fileCacheDirectory, trimmedFileName);
		return file;
	}
	
    /**
     * Allows to add a given array of {@code byte} as a cache file representing by the {@code urlString}.
     *
     * @param urlString
     *            the URL to add to the cache
     * @param bytes
     *            the content of the cache file
	 * @return {@link File}
     */
	public File createFile(final String urlString, final byte[] bytes) {
		final String fileName = DSSUtils.getNormalizedString(urlString);
		final File file = getCacheFile(fileName);
		DSSUtils.saveToFile(bytes, file);
		return file;
	}

	/**
	 * Allows to load the file for a given file name from the cache folder.
	 *
	 * @param urlString {@link String} url
	 * @return the content of the file or {@code null} if the file does not exist
	 * @throws DSSException in case if the file does not exist in the cache
	 */
	public byte[] loadFileFromCache(final String urlString) throws DSSException {
		final String fileName = DSSUtils.getNormalizedString(urlString);
		final File file = getCacheFile(fileName);
		if (file.exists()) {
			final byte[] bytes = DSSUtils.toByteArray(file);
			return bytes;
		}
		throw new DSSException(String.format("The file with URL [%s] does not exist in the cache!", urlString));
	}

	@Override
	public byte[] post(final String urlString, final byte[] content) throws DSSException {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);

		final String fileName = DSSUtils.getNormalizedString(urlString);

		// The length for the InputStreamEntity is needed, because some receivers (on the other side) need this
		// information.
		// To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
		// This is because, it may not be possible to reset the stream (= go to position 0).
		// So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a
		// byte-array.
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, content);
		final String digestHexEncoded = DSSUtils.toHex(digest);
		final String cacheFileName = fileName + "." + digestHexEncoded;
		final File file = getCacheFile(cacheFileName);
		final boolean fileExists = file.exists();
		final boolean isCacheExpired = isCacheExpired(file);

		if (fileExists && !isCacheExpired) {
			LOG.debug("Cached file was used");
			final byte[] byteArray = DSSUtils.toByteArray(file);
			return byteArray;
		} else {
			LOG.debug("There is no cached file!");
		}

		byte[] returnedBytes = null;
		if (isNetworkProtocol(urlString)) {
			returnedBytes = dataLoader.post(urlString, content);
		}
		
		if (Utils.isArrayNotEmpty(returnedBytes)) {
			final File cacheFile = getCacheFile(cacheFileName);
			DSSUtils.saveToFile(returnedBytes, cacheFile);
			return returnedBytes;
		}
		throw new DSSException(String.format("Cannot retrieve data from URL [%s]", urlString));
	}

	private boolean isCacheExpired(File file) {
		if (cacheExpirationTime == null) {
			return false;
		}
		if (!file.exists()) {
			return true;
		}
		long currentTime = new Date().getTime();
		if (currentTime - file.lastModified() > cacheExpirationTime) {
			LOG.debug("Cache is expired");
			return true;
		}
		return false;
	}

	@Override
	public DataAndUrl get(final List<String> urlStrings) {
		if (Utils.isCollectionEmpty(urlStrings)) {
			throw new DSSException("Cannot process the GET call. List of URLs is empty!");
		}
		
		final Map<String, Throwable> exceptions = new HashMap<>(); // store map of exception thrown for urls
		for (final String urlString : urlStrings) {
			LOG.debug("Processing a GET call to URL [{}]...", urlString);
			try {
				final byte[] bytes = get(urlString);
				if (Utils.isArrayEmpty(bytes)) {
					LOG.debug("The retrieved content from URL [{}] is empty. Continue with other URLs...", urlString);
					continue;
				}
				return new DataAndUrl(urlString, bytes);
			} catch (Exception e) {
				LOG.warn("Cannot obtain data using '{}' : {}", urlString, e.getMessage());
				exceptions.put(urlString, e);
			}
		}
		throw new DSSDataLoaderMultipleException(exceptions);
	}

	@Override
	public void setContentType(String contentType) {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);
		dataLoader.setContentType(contentType);
	}
	
}
