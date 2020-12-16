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
package eu.europa.esig.dss.tsl.cache.access;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.dto.builder.DownloadCacheDTOBuilder;
import eu.europa.esig.dss.tsl.dto.builder.ParsingCacheDTOBuilder;
import eu.europa.esig.dss.tsl.dto.builder.ValidationCacheDTOBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * Reads the relevant cache by the given key
 */
public class ReadOnlyCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(ReadOnlyCacheAccess.class);

	/** Global download Cache */
	protected final DownloadCache downloadCache;

	/** Global parsing Cache */
	protected final ParsingCache parsingCache;

	/** Global validation Cache */
	protected final ValidationCache validationCache;

	/**
	 * Default constructor
	 *
	 * @param fileCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public ReadOnlyCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache,
							   final ValidationCache validationCache) {
		this.downloadCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a download cache for an entry with the key [{}]", key);
		return new DownloadCacheDTOBuilder(downloadCache.get(key)).build();
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ParsingCacheDTO getParsingCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a parsing cache for an entry with the key [{}]", key);
		return new ParsingCacheDTOBuilder(parsingCache.get(key)).build();
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ValidationCacheDTO getValidationCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a validation cache for an entry with the key [{}]", key);
		return new ValidationCacheDTOBuilder(validationCache.get(key)).build();
	}

	/**
	 * This method returns all found keys in any cache
	 * 
	 * @return a set of cache keys
	 */
	public Set<CacheKey> getAllCacheKeys() {
		Set<CacheKey> keys = new HashSet<>();
		keys.addAll(downloadCache.getKeys());
		keys.addAll(parsingCache.getKeys());
		keys.addAll(validationCache.getKeys());
		return keys;
	}

}
