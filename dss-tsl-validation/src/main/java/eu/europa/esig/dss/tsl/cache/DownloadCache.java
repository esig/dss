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
package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;

/**
 * The DownloadCache to store files
 *
 */
public class DownloadCache extends AbstractCache<XmlDownloadResult> {

	private static final Logger LOG = LoggerFactory.getLogger(DownloadCache.class);

	/**
	 * Default constructor
	 */
	public DownloadCache() {
		// empty
	}
	
	/**
	 * Checks if the file with the given {@code cacheKey} is up to date
	 * @param cacheKey {@link CacheKey}
	 * @param downloadedResult {@link XmlDownloadResult} value to compare with
	 * @return TRUE if digests match (file is up to date), FALSE otherwise
	 */
	public boolean isUpToDate(CacheKey cacheKey, XmlDownloadResult downloadedResult) {
		LOG.trace("Extracting cached file for the key [{}]...", cacheKey);
		CachedEntry<XmlDownloadResult> cachedFileEntry = get(cacheKey);
		if (!cachedFileEntry.isEmpty()) {
			XmlDownloadResult cachedResult = cachedFileEntry.getCachedResult();
			LOG.trace("Comparing digest of the stored file [{}] with the downloaded file [{}]", cachedResult.getDigest(), downloadedResult.getDigest());
			boolean upToDate = cachedResult.getDigest().equals(downloadedResult.getDigest());
			LOG.trace("Is file with the key [{}] up to date ? {}", cacheKey, upToDate);
			if (upToDate) {
				cachedFileEntry.syncUpdateDate();
			}
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
