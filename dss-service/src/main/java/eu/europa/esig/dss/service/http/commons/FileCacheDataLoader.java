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
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * This class provides some caching features to handle the resources. The default cache folder is set to
 * {@code java.io.tmpdir}. The urls of the resources is transformed to the
 * file name by replacing the special characters by {@code _}
 */
public class FileCacheDataLoader implements DataLoader {

	private static final Logger LOG = LoggerFactory.getLogger(FileCacheDataLoader.class);

	private static final String DATA_LOADER_NOT_CONFIGURED = "The DataLoader is not configured";

	private File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir"));

	private ResourceLoader resourceLoader = new ResourceLoader();

	private List<String> toBeLoaded;

	private List<String> toIgnored;

	private Long cacheExpirationTime;

	private DataLoader dataLoader;

	public FileCacheDataLoader() {
	}

	public FileCacheDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public DataLoader getDataLoader() {
		return dataLoader;
	}

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
	 * @param cacheExpirationTimeInMilliseconds
	 */
	public void setCacheExpirationTime(long cacheExpirationTimeInMilliseconds) {
		this.cacheExpirationTime = cacheExpirationTimeInMilliseconds;
	}

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

			toBeLoaded = new ArrayList<String>();
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

			toIgnored = new ArrayList<String>();
		}
		if (Utils.isStringNotBlank(urlString)) {

			final String normalizedFileName = ResourceLoader.getNormalizedFileName(urlString);
			toIgnored.add(normalizedFileName);
		}
	}

	@Override
	public byte[] get(final String url, final boolean refresh) {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);

		if ((toBeLoaded != null) && !toBeLoaded.contains(url)) {
			return null;
		}
		final String fileName = ResourceLoader.getNormalizedFileName(url);
		final File file = getCacheFile(fileName);
		final boolean fileExists = file.exists();
		final boolean isCacheExpired = isCacheExpired(file);
		if (fileExists && !refresh && !isCacheExpired) {

			LOG.debug("Cached file was used");
			final byte[] bytes = DSSUtils.toByteArray(file);
			return bytes;
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
			final File out = getCacheFile(fileName);
			DSSUtils.saveToFile(bytes, out);
		}
		return bytes;
	}

	private byte[] getLocalFileContent(final String urlString) {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);
		byte[] returnedBytes = null;
		// TODO usage ??
		final String resourcePath = resourceLoader.getAbsoluteResourceFolder(urlString.trim());
		if (resourcePath != null) {
			final File fileResource = new File(resourcePath);
			returnedBytes = DSSUtils.toByteArray(fileResource);
		}
		return returnedBytes;
	}

	@Override
	public byte[] get(final String url) {

		return get(url, false);
	}

	protected boolean isNetworkProtocol(final String urlString) {

		final String normalizedUrl = urlString.trim().toLowerCase();
		return Protocol.isHttpUrl(normalizedUrl) || Protocol.isLdapUrl(normalizedUrl) || Protocol.isFtpUrl(normalizedUrl);
	}

	private File getCacheFile(final String fileName) {

		final String trimmedFileName = fileName.trim();
		if ((toIgnored != null) && toIgnored.contains(trimmedFileName)) {

			throw new DSSException("Part of urls to ignore.");
		}
		LOG.debug("Cached file: {}/{}", fileCacheDirectory, trimmedFileName);
		final File file = new File(fileCacheDirectory, trimmedFileName);
		return file;
	}

	/**
	 * Allows to load the file for a given file name from the cache folder.
	 *
	 * @return the content of the file or {@code null} if the file does not exist
	 */
	public byte[] loadFileFromCache(final String urlString) {

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);
		final File file = getCacheFile(fileName);
		if (file.exists()) {

			final byte[] bytes = DSSUtils.toByteArray(file);
			return bytes;
		}
		return null;
	}

	/**
	 * Allows to add a given array of {@code byte} as a cache file representing by the {@code urlString}.
	 *
	 * @param urlString
	 *            the URL to add to the cache
	 * @param bytes
	 *            the content of the cache file
	 */
	public void saveBytesInCache(final String urlString, final byte[] bytes) {

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);
		final File out = getCacheFile(fileName);
		DSSUtils.saveToFile(bytes, out);
	}

	@Override
	public byte[] post(final String urlString, final byte[] content) throws DSSException {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);

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
		}

		return returnedBytes;
	}

	private boolean isCacheExpired(File file) {
		if (cacheExpirationTime == null) {
			return false;
		}
		if (!file.exists()) {
			return true;
		}
		long currentTime = new Date().getTime();
		if (file.lastModified() + cacheExpirationTime < currentTime) {
			LOG.debug("Cache is expired");
			return true;
		}
		return false;
	}

	@Override
	public DataAndUrl get(final List<String> urlStrings) {

		final int numberOfUrls = urlStrings.size();
		int ii = 0;
		for (final String urlString : urlStrings) {
			try {

				ii++;
				final byte[] bytes = get(urlString);
				if (bytes == null) {
					continue;
				}
				return new DataAndUrl(bytes, urlString);
			} catch (Exception e) {
				if (ii == numberOfUrls) {
					if (e instanceof DSSException) {
						throw (DSSException) e;
					}
					throw new DSSException(e);
				}
				LOG.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		return null;
	}

	@Override
	public void setContentType(String contentType) {
		Objects.requireNonNull(dataLoader, DATA_LOADER_NOT_CONFIGURED);
		dataLoader.setContentType(contentType);
	}
}
