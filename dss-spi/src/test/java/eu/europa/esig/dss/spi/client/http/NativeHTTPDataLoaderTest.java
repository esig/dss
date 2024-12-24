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
package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URLConnection;
import java.time.Duration;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class NativeHTTPDataLoaderTest {

	private static final String HTTP_URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";
	private static final String FILE_URL_TO_LOAD = "file:src/test/resources/belgiumrs2.crt";

	@Test
	void testHttpGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(HTTP_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	void testFileGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(FILE_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	void testGetSmallerThanMaxSize() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setMaxInputSize(1000000);
		byte[] bytesArray = dataLoader.get(FILE_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	void testGetBiggerThanMaxSize() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setMaxInputSize(1);
		assertThrows(DSSException.class, () -> dataLoader.get(FILE_URL_TO_LOAD));
	}

	@Test
	void testConnectTimeout() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setConnectTimeout(1);
		// change URL, as a connection may be already established with the other one
		assertThrows(DSSException.class, () -> dataLoader.get("http://dss.nowina.lu/", true));
	}

	@Test
	void testReadTimeout() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setReadTimeout(1);
		assertThrows(DSSException.class, () -> dataLoader.get(HTTP_URL_TO_LOAD, true));
	}

	@Test
	void unresponsiveServiceTest() throws Exception {
		// Creates a localhost:9090 to simulate an unresponsive service
		try (ServerSocket serverSocket = new ServerSocket(9090, 0, InetAddress.getLoopbackAddress())) {
			MockNativeHTTPDataLoader dataLoader = new MockNativeHTTPDataLoader();

			dataLoader.setReadTimeout(100); // 0.1s is set as a compromise between too long and too small timeout (URLConnection may be not yet instantiated)
			assertThrows(DSSException.class, () -> dataLoader.get("http://localhost:9090"));

			MockNativeDataLoaderCall nativeDataLoaderCall = dataLoader.nativeDataLoaderCall;
			assertNotNull(nativeDataLoaderCall);

			URLConnection connection = nativeDataLoaderCall.connection;
			assertNotNull(connection);

			assertTimeoutPreemptively(Duration.ofMillis(500),
					() -> assertThrows(Exception.class, connection::getInputStream)); // throws an exception when closed
			// NOTE: assert timeout is set to avoid test running indefinitely
		}
	}

	private static class MockNativeHTTPDataLoader extends NativeHTTPDataLoader {

		private static final long serialVersionUID = 8366723398612401709L;

		private MockNativeDataLoaderCall nativeDataLoaderCall;

		@Override
		protected Callable<byte[]> createNativeDataLoaderCall(String url, HttpMethod method, byte[] content, boolean refresh) {
			if (nativeDataLoaderCall == null) {
				nativeDataLoaderCall = new MockNativeDataLoaderCall(
						url, content, refresh, getMaxInputSize(), getConnectTimeout(), getReadTimeout());
			}
			return nativeDataLoaderCall;
		}

	}

	private static class MockNativeDataLoaderCall extends NativeDataLoaderCall {

		private URLConnection connection;

		public MockNativeDataLoaderCall(String url, byte[] content, boolean useCaches, int maxInputSize,
										int connectTimeout, int readTimeout) {
			super(url, content, useCaches, maxInputSize, connectTimeout, readTimeout);
		}

		@Override
		protected URLConnection createConnection() throws IOException {
			if (connection == null) {
				connection = super.createConnection();
			}
			return connection;
		}

	}

}
