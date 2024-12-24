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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingTask;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;

import java.util.concurrent.CountDownLatch;

/**
 * Runs the job for a LOTL analysis
 *
 */
public class LOTLAnalysis extends AbstractRunnableAnalysis {

	/**
	 * Default constructor
	 *
	 * @param source {@link LOTLSource}
	 * @param cacheAccess {@link CacheAccessByKey}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 */
	public LOTLAnalysis(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
						CountDownLatch latch) {
		super(source, cacheAccess, dssFileLoader, latch);
	}

	@Override
	protected AbstractParsingTask<?> getParsingTask(DSSDocument document) {
		return new LOTLParsingTask(document, (LOTLSource) getSource());
	}

}
