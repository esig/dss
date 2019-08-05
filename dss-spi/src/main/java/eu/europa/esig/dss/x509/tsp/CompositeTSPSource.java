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
package eu.europa.esig.dss.x509.tsp;

import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * This class allows to retrieve a timestamp with different sources. The composite will try all sources until to get a
 * non-empty response.
 * 
 * Be careful, all given tspSources MUST accept the same digest algorithm.
 * 
 */
public class CompositeTSPSource implements TSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CompositeTSPSource.class);

	private Map<String, TSPSource> tspSources;

	/**
	 * This setter allows to provide multiple tspSources. Be careful, all given tspSources MUST accept the same digest
	 * algorithm.
	 * 
	 * @param tspSources
	 *            a {@code Map} of String and TSPSource with a label and its corresponding source
	 */
	public void setTspSources(Map<String, TSPSource> tspSources) {
		this.tspSources = tspSources;
	}

	@Override
	public TimeStampToken getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digestValue) throws DSSException {
		for (Entry<String, TSPSource> entry : tspSources.entrySet()) {
			String sourceKey = entry.getKey();
			TSPSource source = entry.getValue();
			LOG.debug("Trying to get timestamp with TSPSource '{}'", sourceKey);
			try {
				TimeStampToken token = source.getTimeStampResponse(digestAlgorithm, digestValue);
				if (token != null) {
					LOG.debug("Successfully retrieved timestamp with TSPSource '{}'", sourceKey);
					return token;
				}
			} catch (Exception e) {
				LOG.warn("Unable to retrieve the timestamp with TSPSource '{}' : {}", sourceKey, e.getMessage());
			}
		}
		throw new DSSException("Unable to retrieve the timestamp (" + tspSources.size() + " tries)");
	}

}
