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
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;

/**
 * Runnable facade to Processes the document validation job (download - parse - validate)
 *
 */
public abstract class AbstractRunnableAnalysis extends AbstractAnalysis implements Runnable {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractRunnableAnalysis.class);

	private static final String LOG_ERROR_PERFORM_ANALYSIS = "Error performing analysis.";

	/** The tasks counter */
	private final CountDownLatch latch;

	/**
	 * Default constructor
	 *
	 * @param source {@link DocumentSource} representing a document
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 * @deprecated since DSS 6.6. Please use
	 *             {@link AbstractRunnableAnalysis(DocumentSource, CacheAccessByKey, DSSFileLoader, CountDownLatch, ValidationPolicy)}.
	 */
	@Deprecated
	protected AbstractRunnableAnalysis(final DocumentSource source, final CacheAccessByKey cacheAccess,
                                       final DSSFileLoader dssFileLoader, CountDownLatch latch) {
		this(source, cacheAccess, dssFileLoader, latch, null);
	}

	/**
	 * Default constructor
	 *
	 * @param source {@link DocumentSource} representing a document
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	protected AbstractRunnableAnalysis(final DocumentSource source, final CacheAccessByKey cacheAccess,
									   final DSSFileLoader dssFileLoader, final CountDownLatch latch,
									   ValidationPolicy validationPolicy) {
		super(source, cacheAccess, dssFileLoader, validationPolicy);
		this.latch = latch;
	}

	/**
	 * Performs analysis
	 */
	protected void doAnalyze() {
		DSSDocument document = download(getSource().getUrl());
		if (document != null) {
			parsing(document);
			validation(document, getCurrentCertificateSource());
		}
	}

	/**
	 * Returns the certificate source to be used to validate document
	 *
	 * @return {@link CertificateSource}
	 */
	protected CertificateSource getCurrentCertificateSource() {
		return getSource().getCertificateSource();
	}

	@Override
	public void run() {
		try {
			this.doAnalyze();
		} catch (final Throwable exception) {
			// NOTE: Throwable shall be caught
			LOG.warn(LOG_ERROR_PERFORM_ANALYSIS, exception);
		} finally {
			latch.countDown();
		}
	}

}
