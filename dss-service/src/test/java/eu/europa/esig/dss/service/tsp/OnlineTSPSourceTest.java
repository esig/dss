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
package eu.europa.esig.dss.service.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;

public class OnlineTSPSourceTest {

	private static final String TSA_URL = "http://dss.nowina.lu/pki-factory/tsa/good-tsa";

	@Test
	public void testWithoutNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new TimestampDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Disabled("Content-type is required")
	public void testWithCommonDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new CommonsDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithTimestampDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource("http://demo.sk.ee/tsa/");
		tspSource.setPolicyOid("0.4.0.2023.1.1");
		tspSource.setDataLoader(new TimestampDataLoader()); // content-type is different

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA512, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA512, digest);
		assertNotNull(timeStampResponse);
	}

	@Disabled("Content-type is required")
	public void testWithNativeHTTPDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new NativeHTTPDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testWithNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new TimestampDataLoader());
		tspSource.setNonceSource(new SecureRandomNonceSource());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
	}

	@Test
	public void testNotTSA() {
		Exception exception = assertThrows(DSSException.class, () -> {
			OnlineTSPSource tspSource = new OnlineTSPSource();
			tspSource.setDataLoader(new TimestampDataLoader());
			tspSource.setTspServer("http://www.google.com");

			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
			tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		});
		assertEquals("Unable to process POST call for url 'http://www.google.com'", exception.getMessage());
	}

}
