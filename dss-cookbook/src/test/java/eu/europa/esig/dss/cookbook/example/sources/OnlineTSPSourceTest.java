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

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

/**
 * How to initialize online TSP source.
 */
public class OnlineTSPSourceTest {

	@Test
	public void test() throws IOException {

		// tag::demo[]

		final String tspServer = "http://services.globaltrustfinder.com/adss/tsa";
		OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
		tspSource.setPolicyOid("1.2.3.4.5");

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
		final byte[] toDigest = "digest value".getBytes();
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
		final TimeStampToken tsr = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);

		System.out.println(DSSUtils.toHex(tsr.getEncoded()));

		// end::demo[]

		assertNotNull(tsr);
	}
	
	
	@Test
	public void testTLS() throws IOException {

		// tag::demo[]

		final String tspServer = "https://localhost:8082";
		OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
		tspSource.setPolicyOid("1.2.3.4.5");

		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
		final byte[] toDigest = "digest value".getBytes();
		final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
		final TimeStampToken tsr = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digestValue,IOUtils.toByteArray(OnlineTSPSourceTest.class.getResourceAsStream("/tsa.p12")), "password");

		System.out.println(DSSUtils.toHex(tsr.getEncoded()));

		// end::demo[]

		assertNotNull(tsr);
	}
}
