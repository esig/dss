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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processes the LOTL/TL validation job (download - parse - validate)
 *
 */
public abstract class AbstractAnalysis  {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAnalysis.class);

	/** The TL/LOTL source */
	private final TLSource source;

	/** The cache access of the record */
	private final CacheAccessByKey cacheAccess;

	/** The file loader */
	private final DSSFileLoader dssFileLoader;
	
	/**
	 * Default constructor
	 *
	 * @param source {@link TLSource} representing a TL or LOTL
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	protected AbstractAnalysis(final TLSource source, final CacheAccessByKey cacheAccess, final DSSFileLoader dssFileLoader) {
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
	}

	/**
	 * Returns the current {@code TLSource}
	 *
	 * @return {@link TLSource}
	 */
	protected final TLSource getSource() {
		return source;
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
				expireCache();
			}
			document = downloadResult.getDSSDocument();
		} catch (Exception e) {
			// wrapped exception
			LOG.warn(e.getMessage());
			cacheAccess.downloadError(e);
		}
		return document;
	}

	/**
	 * This method expires the cache in order to trigger the corresponding tasks on refresh
	 */
	protected void expireCache() {
		cacheAccess.expireParsing();
		cacheAccess.expireValidation();
	}

	/**
	 * Parses the document
	 *
	 * @param document {@link DSSDocument} to parse
	 */
	protected void parsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.debug("Parsing the TL/LOTL with cache key '{}'...", cacheAccess.getCacheKey().getKey());
				AbstractParsingTask<?> parsingTask = getParsingTask(document);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.warn("Cannot parse the TL/LOTL with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage(), e);
				cacheAccess.parsingError(e);
			}
		}
	}

	/**
	 * Returns the corresponding parsing task for the source on the given document
	 *
	 * @param document {@link DSSDocument} to parse
	 * @return {@link AbstractParsingTask} to be executed
	 */
	protected abstract AbstractParsingTask<?> getParsingTask(DSSDocument document);
	
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
				TLValidatorTask validationTask = getValidationTask(document, certificateSource);
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.warn("Cannot validate the TL/LOTL with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage());
				cacheAccess.validationError(e);
			}
		}
	}

	/**
	 * Returns the corresponding validation task for the source on the given document using the provided certificate source
	 *
	 * @param document {@link DSSDocument} to parse
	 * @param  certificateSource {@link CertificateSource} to use for validation
	 * @return {@link TLValidatorTask} to be executed
	 */
	protected TLValidatorTask getValidationTask(DSSDocument document, CertificateSource certificateSource) {
		return new TLValidatorTask(document, certificateSource);
	}

}
