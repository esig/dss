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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader.DataAndUrl;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CommonsDataLoaderTest {

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";
	private static final String TIMEOUT_URL = "https://dss.nowina.lu/pki-factory/crl/timeout/1/good-ca.crl";

	private CommonsDataLoader dataLoader;

	@BeforeEach
	void init() {
		dataLoader = new CommonsDataLoader();
	}

	@Test
	void testGet() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		NativeHTTPDataLoader dataLoader2 = new NativeHTTPDataLoader();
		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD);

		assertArrayEquals(bytesArray, bytesArrays2);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	void ldapTest1() {
		String url = "ldap://directory.d-trust.net/CN=D-TRUST%20CA%203-1%202016,O=D-Trust%20GmbH,C=DE?cACertificate?base?";
		getDataAndAssertNotNull(url);
	}

	@Test
	void ldapTest2() {
		String url = "ldap://directory.d-trust.net/CN=D-TRUST%20CA%203-1%202016,O=D-Trust%20GmbH,C=DE?certificaterevocationlist";
		getDataAndAssertNotNull(url);
	}

	@Test
	void ldapWithTrustedHostNamesTest() {
		CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
		String url = "ldap://directory.d-trust.net/CN=D-TRUST%20CA%203-1%202016,O=D-Trust%20GmbH,C=DE?cACertificate?base?";
		assertTrue(Utils.isArrayNotEmpty(commonsDataLoader.get(url)));

		commonsDataLoader.setLdapTrustedHostnames(null);
		assertTrue(Utils.isArrayNotEmpty(commonsDataLoader.get(url)));

		commonsDataLoader.setLdapTrustedHostnames(Collections.emptyList());
		Exception exception = assertThrows(DSSExternalResourceException.class, () -> commonsDataLoader.get(url));
		assertEquals(String.format("Cannot get data from URL [%s]. " +
				"Reason : [Untrusted host name 'directory.d-trust.net']", url), exception.getMessage());

		commonsDataLoader.setLdapTrustedHostnames(Collections.singletonList("trusted.url.com"));
		exception = assertThrows(DSSExternalResourceException.class, () -> commonsDataLoader.get(url));
		assertEquals(String.format("Cannot get data from URL [%s]. " +
				"Reason : [Untrusted host name 'directory.d-trust.net']", url), exception.getMessage());

		commonsDataLoader.setLdapTrustedHostnames(Collections.singletonList("d-trust.net"));
		exception = assertThrows(DSSExternalResourceException.class, () -> commonsDataLoader.get(url));
		assertEquals(String.format("Cannot get data from URL [%s]. " +
				"Reason : [Untrusted host name 'directory.d-trust.net']", url), exception.getMessage());

		commonsDataLoader.setLdapTrustedHostnames(Collections.singletonList("directory.d-trust.net"));
		assertTrue(Utils.isArrayNotEmpty(commonsDataLoader.get(url)));

		commonsDataLoader.setLdapTrustedHostnames(Arrays.asList("trusted.url.com", "directory.d-trust.net"));
		assertTrue(Utils.isArrayNotEmpty(commonsDataLoader.get(url)));
	}

	@Test
	void dss1583test() {
		String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems%20International%20GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH,c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH%20,%20c=de%20";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH , c=de";
		getDataAndAssertNotNull(url);
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificateRevocationList?base";
		getDataAndAssertNotNull(url);
	}

	private void getDataAndAssertNotNull(String url) {
		try {
			assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		} catch (DSSExternalResourceException e) {
			fail(String.format("Failed to obtain data from an external source. Reason : [%s])", e.getMessage()), e);
		}
	}

	@Test
	void dss1583WarningTest() {
		assertThrows(DSSExternalResourceException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de%2";
			dataLoader.get(url);
		});
		assertThrows(DSSExternalResourceException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Syste%ms International GmbH,c=de";
			dataLoader.get(url);
		});
		assertThrows(DSSExternalResourceException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-SystemsInternational GmbH,c=de";
			dataLoader.get(url);
		});
		assertThrows(DSSExternalResourceException.class, () -> {
			String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificate";
			dataLoader.get(url);
		});
	}

	@Test
	void timeoutTest() {
		// no timeout
		assertNotNull(dataLoader.get(TIMEOUT_URL));

		dataLoader.setTimeoutConnection(1);
		DSSExternalResourceException exception = assertThrows(DSSExternalResourceException.class,
				() -> dataLoader.get(TIMEOUT_URL));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [" + TIMEOUT_URL + "]"));

		dataLoader.setTimeoutConnection(60000);
		dataLoader.setTimeoutResponse(1);
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(TIMEOUT_URL));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [" + TIMEOUT_URL + "]"));
	}

	@Test
	void resourceDoesNotExistTest() {
		dataLoader.setTimeoutConnection(1);
		DSSExternalResourceException exception = assertThrows(DSSExternalResourceException.class,
				() -> dataLoader.get("http://wrong.url"));
		assertTrue(exception.getMessage().startsWith("Unable to process GET call for url [http://wrong.url]"));
	}

	@Test
	void multipleDataLoadTest() {
		byte[] firstUrlData = dataLoader.get(URL_TO_LOAD);
		DataAndUrl dataAndUrl = dataLoader.get(Arrays.asList(URL_TO_LOAD, "http://ncrl.ssc.lt/class3nqc/cacrl.crl",
				"http://www.ssc.lt/cacert/ssc_class3nqc.crt"));
		assertEquals(URL_TO_LOAD, dataAndUrl.getUrlString());
		assertArrayEquals(firstUrlData, dataAndUrl.getData());

		dataAndUrl = dataLoader.get(Arrays.asList("http://wrong.url", "does_not_exist", URL_TO_LOAD));
		assertEquals(URL_TO_LOAD, dataAndUrl.getUrlString());
        assertArrayEquals(firstUrlData, dataAndUrl.getData());

	}

	@Test
	void multipleDataLoaderExceptionTest() {
		dataLoader.setTimeoutConnection(1);

		List<String> urls = Arrays.asList("http://wrong.url", "does_not_exist", TIMEOUT_URL);
		DSSDataLoaderMultipleException exception = assertThrows(DSSDataLoaderMultipleException.class,
				() -> dataLoader.get(urls));
		assertTrue(exception.getMessage().contains("http://wrong.url"));
		assertTrue(exception.getMessage().contains("does_not_exist"));
		assertTrue(exception.getMessage().contains(TIMEOUT_URL));
	}

	@Test
	void negativeTimeoutTest() {
		// negative values enforce to use system properties
		dataLoader.setTimeoutConnection(-1);
		dataLoader.setTimeoutConnectionRequest(-1);
		dataLoader.setTimeoutResponse(-1);
		dataLoader.setTimeoutSocket(-1);
		dataLoader.setConnectionKeepAlive(-1);
		dataLoader.setConnectionTimeToLive(-1);

		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));
	}

	@Test
	void excludedHostsTest() {
		ProxyProperties proxyProperties = new ProxyProperties();
		proxyProperties.setHost("1.2.4.5.6");
		proxyProperties.setPort(8080);

		ProxyConfig proxyConfig = new ProxyConfig();
		proxyConfig.setHttpProperties(proxyProperties);

		dataLoader.setProxyConfig(proxyConfig);

		Exception exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("certs.eid.belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("certs.eid.belgium.be", "google.com"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("CERTS.EID.BELGIUM.BE"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*.eid.belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("certs.eid.belgium.be", "*.eid.belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*.EID.BELGIUM.BE"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*.belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("*.belgium.be", "*..belgium.be"));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("google.com", "wikipedia.org"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*.*.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("certs.*.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*s.eid.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*..belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("**.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Arrays.asList("*..belgium.be", "**.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));

		proxyProperties.setExcludedHosts(Collections.singleton("*.certs.eid.belgium.be"));
		exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertTrue(exception.getMessage().contains(String.format("Unable to process GET call for url [%s].", URL_TO_LOAD)));
	}

	@Test
	void httpClientResponseHandlerTest() {
		CommonsHttpClientResponseHandler httpClientResponseHandler = new CommonsHttpClientResponseHandler();
		dataLoader.setHttpClientResponseHandler(httpClientResponseHandler);
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Collections.singletonList(HttpStatus.SC_OK));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_CONTINUE));
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(URL_TO_LOAD)));

		httpClientResponseHandler.setAcceptedHttpStatuses(Collections.singletonList(HttpStatus.SC_CONTINUE));
		Exception exception = assertThrows(DSSExternalResourceException.class, () -> dataLoader.get(URL_TO_LOAD));
		assertEquals("Unable to process GET call for url [http://certs.eid.belgium.be/belgiumrs2.crt]. " +
				"Reason : [Not acceptable HTTP Status (HTTP status code : 200 / reason : OK)]", exception.getMessage());
	}

}
