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
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * How to initialize online TSP source.
 */
public class OnlineTSPSourceTest {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineTSPSourceTest.class);

	@Test
	public void test() throws IOException {

		// tag::demo[]
		// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
		// import eu.europa.esig.dss.model.TimestampBinary;
		// import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
		// import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
		// import eu.europa.esig.dss.spi.DSSUtils;

		final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";
		OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
		tspSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-type

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
		final byte[] toDigest = "Hello world".getBytes("UTF-8");
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
		final TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

		LOG.info(DSSUtils.toHex(tsBinary.getBytes()));

		// end::demo[]

		assertNotNull(tsBinary);
	}

	public void policySnippet() {
		final String tspServer = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";

		// tag::policy[]
		// import eu.europa.esig.dss.service.tsp.OnlineTSPSource;

		OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
		tspSource.setPolicyOid("0.4.0.2023.1.1"); // provide a policy OID

		// end::policy[]

	}

}
