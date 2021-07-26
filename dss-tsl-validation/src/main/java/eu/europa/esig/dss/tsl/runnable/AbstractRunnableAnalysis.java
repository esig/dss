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

import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;

/**
 * Runnable facade to Processes the LOTL/TL validation job (download - parse - validate)
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
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 */
	protected AbstractRunnableAnalysis(final CacheAccessByKey cacheAccess, final DSSFileLoader dssFileLoader, CountDownLatch latch) {
		super(cacheAccess,dssFileLoader);
		this.latch = latch;
	}

	/**
	 * Performs analysis
	 */
	protected abstract void doAnalyze();

	@Override
	public void run() {
		try {
			this.doAnalyze();
		} catch(final Throwable exception) {
			LOG.error(LOG_ERROR_PERFORM_ANALYSIS, exception);
		} finally {
			latch.countDown();
		}
	}

}
