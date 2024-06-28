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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.OnlineSourceTest;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OnlineTSPSourceTest extends OnlineSourceTest {

	private static final String TSA_URL = ONLINE_PKI_HOST + "/tsa/good-tsa";
	private static final String ED25519_TSA_URL = ONLINE_PKI_HOST + "/tsa/Ed25519-good-tsa";
	private static final String ERROR_500_TSA_URL = ONLINE_PKI_HOST + "/tsa/error-500/good-tsa";
	private static final String INVALID_SIG_TSA_URL = ONLINE_PKI_HOST + "/tsa/invalid/good-tsa";
	private static final String TIMEOUT_TSA_URL = ONLINE_PKI_HOST + "/tsa/timeout/good-tsa";
	private static final String CUSTOM_TIMEOUT_TSA_URL = ONLINE_PKI_HOST + "/tsa/timeout/%s/good-tsa";

	@Test
	void testWithoutNonce() throws Exception {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));

		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		assertTrue(timestampToken.isSignedBy(timestampToken.getCandidatesForSigningCertificate().getTheBestCandidate().getCertificateToken()));
		assertTrue(timestampToken.matchData(digest, true));
		assertTrue(timestampToken.isValid());
	}

	@Test
	void error500() {
		OnlineTSPSource tspSource = new OnlineTSPSource(ERROR_500_TSA_URL);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		assertThrows(DSSExternalResourceException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));

		Map<String, TSPSource> tspSources = new HashMap<>();
		tspSources.put("A", tspSource);
		tspSources.put("B", tspSource);

		CompositeTSPSource compositeTSPSource = new CompositeTSPSource();
		compositeTSPSource.setTspSources(tspSources);
		assertThrows(DSSExternalResourceException.class, () -> compositeTSPSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
	}

	@Test
	void invalidSignature() throws Exception {
		OnlineTSPSource tspSource = new OnlineTSPSource(INVALID_SIG_TSA_URL);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));

		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		assertFalse(timestampToken.isSignedBy(timestampToken.getCandidatesForSigningCertificate().getTheBestCandidate().getCertificateToken()));
		assertTrue(timestampToken.matchData(digest, true));
		assertFalse(timestampToken.isValid());
	}

	@Test
	void timeout() throws Exception {
		TimestampDataLoader timestampDataLoader = new TimestampDataLoader();
		timestampDataLoader.setTimeoutResponse(1000); // 1 second
		OnlineTSPSource tspSource = new OnlineTSPSource(TIMEOUT_TSA_URL, timestampDataLoader);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		assertThrows(DSSExternalResourceException.class, () -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
	}

	@Test
	void timeoutCustom() throws Exception {
		TimestampDataLoader timestampDataLoader = new TimestampDataLoader();
		timestampDataLoader.setTimeoutResponse(1000); // 1 second

		OnlineTSPSource lowTimeoutTspSource = new OnlineTSPSource(String.format(CUSTOM_TIMEOUT_TSA_URL, 1), timestampDataLoader);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());

		TimestampBinary timeStampResponse = lowTimeoutTspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));

		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		assertTrue(timestampToken.isSignedBy(timestampToken.getCandidatesForSigningCertificate().getTheBestCandidate().getCertificateToken()));
		assertTrue(timestampToken.matchData(digest, true));
		assertTrue(timestampToken.isValid());

		OnlineTSPSource bigTimeoutTspSource = new OnlineTSPSource(String.format(CUSTOM_TIMEOUT_TSA_URL, 2000), timestampDataLoader);;

		assertThrows(DSSExternalResourceException.class, () -> bigTimeoutTspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
	}

    @Test
    void composite() {
        OnlineTSPSource errorTspSource = new OnlineTSPSource(ERROR_500_TSA_URL);
        OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);

        Map<String, TSPSource> tspSources = new HashMap<>();
        tspSources.put("A", errorTspSource);
        tspSources.put("B", tspSource);

        CompositeTSPSource compositeTSPSource = new CompositeTSPSource();
        compositeTSPSource.setTspSources(tspSources);

        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
        assertNotNull(compositeTSPSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
    }

	@Test
	void testEd25519WithoutNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(ED25519_TSA_URL, new TimestampDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));
	}

	@Disabled("Content-type is required")
	void testWithCommonDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL, new CommonsDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));
	}

	@Test
	void testWithTimestampDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource("http://demo.sk.ee/tsa/");
		tspSource.setPolicyOid("0.4.0.2023.1.1");
        TimestampDataLoader dataLoader = new TimestampDataLoader();
        assertThrows(UnsupportedOperationException.class, () -> dataLoader.setContentType("application/ocsp-request"));
        tspSource.setDataLoader(dataLoader); // content-type is different

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA512, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA512, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));
	}

	@Disabled("Content-type is required")
	void testWithNativeHTTPDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(new NativeHTTPDataLoader());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));
	}

	@Test
	void testWithNonce() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setNonceSource(new SecureRandomNonceSource());

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		assertNotNull(timeStampResponse);
		assertTrue(Utils.isArrayNotEmpty(timeStampResponse.getBytes()));
	}

	@Test
	void testNotTSA() {
		OnlineTSPSource tspSource = new OnlineTSPSource();
		tspSource.setTspServer("http://www.google.com");

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());

		Exception exception = assertThrows(DSSException.class,
				() -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
		assertTrue(exception.getMessage().contains("Unable to process POST call for url [http://www.google.com]"));
	}

	@Test
	void testNullDataLoader() {
		OnlineTSPSource tspSource = new OnlineTSPSource(TSA_URL);
		tspSource.setDataLoader(null);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, "Hello world".getBytes());
		Exception exception = assertThrows(NullPointerException.class,
				() -> tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, digest));
		assertEquals("DataLoader is not provided !", exception.getMessage());
	}

}
