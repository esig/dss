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

public final class CacheAccessFactory {

	/* Global Cache */
	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public CacheAccessFactory() {
		downloadCache = new DownloadCache();
		parsingCache = new ParsingCache();
		validationCache = new ValidationCache();
	}

	public CacheAccessByKey getCacheAccess(CacheKey key) {
		return new CacheAccessByKey(key, downloadCache, parsingCache, validationCache);
	}

	public TLChangesCacheAccess getTLChangesCacheAccess() {
		return new TLChangesCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		return new ReadOnlyCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public SynchronizerCacheAccess getSynchronizerCacheAccess() {
		return new SynchronizerCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public DebugCacheAccess getDebugCacheAccess() {
		return new DebugCacheAccess(downloadCache, parsingCache, validationCache);
	}

}
