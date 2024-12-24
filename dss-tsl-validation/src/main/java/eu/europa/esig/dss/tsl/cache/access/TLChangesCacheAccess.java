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

/**
 * Forces an update of a TL validation
 */
public class TLChangesCacheAccess {

	/** Global download Cache */
	private final DownloadCache downloadCache;

	/** Global parsing Cache */
	private final ParsingCache parsingCache;

	/** Global validation Cache */
	private final ValidationCache validationCache;

	/**
	 * Default constructor
	 *
	 * @param downloadCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public TLChangesCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache,
								final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	/**
	 * Sets 'toBeDeleted' status for all records with the given key
	 *
	 * @param cacheKey {@link CacheKey}
	 */
	public void toBeDeleted(CacheKey cacheKey) {
		downloadCache.toBeDeleted(cacheKey);
		parsingCache.toBeDeleted(cacheKey);
		validationCache.toBeDeleted(cacheKey);
	}

	/**
	 * Sets the expired status for the validation record for the {@code cacheKey}
	 *
	 * @param cacheKey {@link CacheKey}
	 */
	public void expireSignatureValidation(CacheKey cacheKey) {
		validationCache.expire(cacheKey);
	}

}
