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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

/**
 * Generates a prints a report of the current cache state
 */
public class DebugCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(DebugCacheAccess.class);

	/** New line character */
	private static final String CARRIAGE_RETURN = "\n";

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
	public DebugCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache,
							final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	/**
	 * Prints the report for the current cache state
	 */
	public void dump() {
		StringBuilder sb = new StringBuilder("Cache contents");
		sb.append(CARRIAGE_RETURN);
		sb.append(downloadCache.dump());
		sb.append(CARRIAGE_RETURN);
		sb.append(parsingCache.dump());
		sb.append(CARRIAGE_RETURN);
		sb.append(validationCache.dump());
		LOG.info(sb.toString());
	}

}
