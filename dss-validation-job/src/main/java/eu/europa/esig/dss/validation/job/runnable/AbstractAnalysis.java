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
package eu.europa.esig.dss.validation.job.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.cache.access.ReadOnlyCacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadResult;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processes the document/document list validation job (download - parse - validate)
 *
 */
public abstract class AbstractAnalysis {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAnalysis.class);

	/** The document/document list source */
	private final DocumentSource source;

	/** The cache access of the record */
	private final CacheAccessByKey cacheAccess;

	/** The file loader */
	private final DSSFileLoader dssFileLoader;

	/** Validation policy constraints */
	private final ValidationPolicy validationPolicy;
	
	/**
	 * Default constructor
	 *
	 * @param source {@link DocumentSource} representing a document
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @deprecated since DSS 6.6. Please use
	 *             {@link AbstractAnalysis(DocumentSource, CacheAccessByKey,DSSFileLoader, ValidationPolicy)} instead.
	 */
	@Deprecated
	protected AbstractAnalysis(final DocumentSource source, final CacheAccessByKey cacheAccess,
							   final DSSFileLoader dssFileLoader) {
		this(source, cacheAccess, dssFileLoader, null);
	}

	/**
	 * Default constructor
	 *
	 * @param source {@link DocumentSource} representing a document
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	protected AbstractAnalysis(final DocumentSource source, final CacheAccessByKey cacheAccess,
							   final DSSFileLoader dssFileLoader, final ValidationPolicy validationPolicy) {
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
		this.validationPolicy = validationPolicy;
	}

	/**
	 * Returns the current {@code DocumentSource}
	 *
	 * @return {@link DocumentSource}
	 */
	protected DocumentSource getSource() {
		return source;
	}

	/**
	 * Gets the {@code ReadOnlyCacheAccessByKey}
	 *
	 * @return {@link ReadOnlyCacheAccessByKey}
	 */
	protected final ReadOnlyCacheAccessByKey getCacheAccessByKey() {
		return cacheAccess;
	}

	/**
	 * Returns the defined {@code ValidationPolicy}
	 *
	 * @return {@link ValidationPolicy}
	 */
	protected ValidationPolicy getValidationPolicy() {
		return validationPolicy;
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
			DownloadTask downloadTask = getDownloadTask(dssFileLoader, url);
			DownloadResult downloadResult = downloadTask.get();
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
	 * Returns the corresponding download task for the source on the given document
	 *
	 * @param dssFileLoader {@link DSSFileLoader} to use for document download
	 * @param url {@link String}
	 * @return {@link DownloadTask} to be executed
	 */
	protected abstract DownloadTask getDownloadTask(DSSFileLoader dssFileLoader, String url);

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
		// True if EMPTY / EXPIRED by a document / document list
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.debug("Parsing the document with cache key '{}'...", cacheAccess.getCacheKey().getKey());
				ParsingTask parsingTask = getParsingTask(document);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.warn("Cannot parse the document with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage(), e);
				cacheAccess.parsingError(e);
			}
		}
	}

	/**
	 * Returns the corresponding parsing task for the source on the given document
	 *
	 * @param document {@link DSSDocument} to parse
	 * @return {@link ParsingTask} to be executed
	 */
	protected abstract ParsingTask getParsingTask(DSSDocument document);
	
	/**
	 * Validates the document
	 *
	 * @param document {@link DSSDocument} to validate
	 * @param certificateSource {@link CertificateSource} to use
	 */
	protected void validation(DSSDocument document, CertificateSource certificateSource) {
		// True if EMPTY / EXPIRED by document
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				LOG.debug("Validating the document with cache key '{}'...", cacheAccess.getCacheKey().getKey());
				ValidationTask validationTask = getValidationTask(document, certificateSource);
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.warn("Cannot validate the document with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage());
				cacheAccess.validationError(e);
			}
		}
	}

	/**
	 * Returns the corresponding validation task for the source on the given document using the provided certificate source
	 *
	 * @param document {@link DSSDocument} to parse
	 * @param  certificateSource {@link CertificateSource} to use for validation
	 * @return {@link ValidationTask} to be executed
	 */
	protected abstract ValidationTask getValidationTask(DSSDocument document, CertificateSource certificateSource);

}
