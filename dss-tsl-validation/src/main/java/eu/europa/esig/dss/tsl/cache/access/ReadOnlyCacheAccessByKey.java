/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.cache.access;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;

/**
 * The class prevents reading of other records but the one with defined key
 */
public class ReadOnlyCacheAccessByKey {

	/** Key of the CacheEntry */
	protected final CacheKey key;

	/** Global download Cache */
	protected final DownloadCache downloadCache;

	/** Global parsing Cache */
	protected final ParsingCache parsingCache;

	/** Global validation Cache */
	protected final ValidationCache validationCache;

	/** Reads a cache by the given key */
	private final ReadOnlyCacheAccess readOnlyCacheAccess;

	/**
	 * Default constructor
	 *
	 * @param key {@link CacheKey} to read
	 * @param downloadCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public ReadOnlyCacheAccessByKey(final CacheKey key, final DownloadCache downloadCache,
									final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.key = key;
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
		this.readOnlyCacheAccess = new ReadOnlyCacheAccess(downloadCache, parsingCache, validationCache);
	}

	/**
	 * Returns the cached read-only download result DTO
	 * 
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadReadOnlyResult() {
		return readOnlyCacheAccess.getDownloadCacheDTO(key);
	}

	/**
	 * Returns the cached read-only parsing result DTO
	 * 
	 * @return {@link ParsingCacheDTO}
	 */
	public ParsingCacheDTO getParsingReadOnlyResult() {
		return readOnlyCacheAccess.getParsingCacheDTO(key);
	}

	/**
	 * Returns the cached read-only validation result DTO
	 * 
	 * @return {@link ValidationCacheDTO}
	 */
	public ValidationCacheDTO getValidationReadOnlyResult() {
		return readOnlyCacheAccess.getValidationCacheDTO(key);
	}

}
