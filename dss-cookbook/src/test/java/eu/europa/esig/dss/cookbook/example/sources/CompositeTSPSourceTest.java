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
package eu.europa.esig.dss.cookbook.example.sources;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * How to configure a Composite TSP Source.
 */
class CompositeTSPSourceTest {

	private static final Logger LOG = LoggerFactory.getLogger(CompositeTSPSourceTest.class);

	@Test
	void test() throws IOException {

		// tag::demo[]
		// import java.util.HashMap;
		// import java.util.Map;
		// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
		// import eu.europa.esig.dss.model.TimestampBinary;
		// import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
		// import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
		// import eu.europa.esig.dss.spi.DSSUtils;
		// import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
		// import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

		// Create a map with several TSPSources
		TimestampDataLoader timestampDataLoader = new TimestampDataLoader();// uses the specific content-type

		OnlineTSPSource tsa1 = new OnlineTSPSource("http://dss.nowina.lu/pki-factory/tsa/ee-good-tsa");
		tsa1.setDataLoader(timestampDataLoader);
		OnlineTSPSource tsa2 = new OnlineTSPSource("http://dss.nowina.lu/pki-factory/tsa/good-tsa");
		tsa2.setDataLoader(timestampDataLoader);

		Map<String, TSPSource> tspSources = new HashMap<>();
		tspSources.put("TSA1", tsa1);
		tspSources.put("TSA2", tsa2);

		// Instantiate a new CompositeTSPSource and set the different sources
		CompositeTSPSource tspSource = new CompositeTSPSource();
		tspSource.setTspSources(tspSources);

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
		final byte[] toDigest = "Hello world".getBytes("UTF-8");
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);

		// DSS will request the tsp sources (one by one) until getting a valid token.
		// If none of them succeeds, a DSSException is thrown.
		final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

		// end::demo[]

		LOG.info(DSSUtils.toHex(tsBinary.getBytes()));
		assertNotNull(tsBinary);
	}

}
