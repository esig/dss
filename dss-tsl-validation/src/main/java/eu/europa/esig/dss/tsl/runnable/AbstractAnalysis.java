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
package eu.europa.esig.dss.tsl.runnable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

/**
 * Processes the LOTL/TL validation job (download - parse - validate)
 *
 */
public abstract class AbstractAnalysis  {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAnalysis.class);

	/** The cache access of the record */
	private final CacheAccessByKey cacheAccess;

	/** The file loader */
	private final DSSFileLoader dssFileLoader;
	
	/**
	 * Default constructor
	 *
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	protected AbstractAnalysis(final CacheAccessByKey cacheAccess, final DSSFileLoader dssFileLoader) {
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
	}

	/**
	 * Downloads the document by url
	 *
	 * @param url {@link String}
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument download(final String url) {
		DSSDocument document = null;
		try {
			LOG.debug("Downloading url '{}'...", url);
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, url);
			XmlDownloadResult downloadResult = downloadTask.get();
			if (!cacheAccess.isUpToDate(downloadResult)) {
				cacheAccess.update(downloadResult);
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
			}
			document = downloadResult.getDSSDocument();
		} catch (Exception e) {
			// wrapped exception
			LOG.error(e.getMessage());
			cacheAccess.downloadError(e);
		}
		return document;
	}

	/**
	 * Gets the {@code CacheAccessByKey}
	 *
	 * @return {@link CacheAccessByKey}
	 */
	protected final CacheAccessByKey getCacheAccessByKey() {
		return cacheAccess;
	}

	/**
	 * Parses the document
	 *
	 * @param document {@link DSSDocument} to parse
	 * @param source {@link LOTLSource}
	 */
	protected void lotlParsing(DSSDocument document, LOTLSource source) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.debug("Parsing LOTL with cache key '{}'...", source.getCacheKey().getKey());
				LOTLParsingTask parsingTask = new LOTLParsingTask(document, source);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.error("Cannot parse the LOTL with the cache key '{}' : {}", source.getCacheKey().getKey(), e.getMessage(), e);
				cacheAccess.parsingError(e);
			}
		}
	}
	
	/**
	 * Validates the document
	 *
	 * @param document {@link DSSDocument} to validate
	 * @param certificateSource {@link CertificateSource} to use
	 */
	protected void validation(DSSDocument document, CertificateSource certificateSource) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				LOG.debug("Validating the TL/LOTL with cache key '{}'...", cacheAccess.getCacheKey().getKey());
				TLValidatorTask validationTask = new TLValidatorTask(document, certificateSource);
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.error("Cannot validate the TL/LOTL with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage());
				cacheAccess.validationError(e);
			}
		}
	}

}
