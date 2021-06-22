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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SSLCertificateLoaderTest {
	
	@Test
	public void test() throws Exception {
		String url = "https://wikipedia.org";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		List<CertificateToken> certificateTokens = sslCertificateDataLoader.getCertificates(url);
		assertTrue(Utils.isCollectionNotEmpty(certificateTokens));
	}
	
	@Test
	public void wrongUrl() throws Exception {
		String url = "https://wrong.url";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Exception exception = assertThrows(DSSExternalResourceException.class, () -> sslCertificateDataLoader.getCertificates(url));
		assertTrue(exception.getMessage().contains("Unable to process GET call for url [https://wrong.url]"));
	}
	
	@Test
	public void urlWithSpaces() throws Exception {
		String url = " https://wikipedia.org  ";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		List<CertificateToken> certificateTokens = sslCertificateDataLoader.getCertificates(url);
		assertTrue(Utils.isCollectionNotEmpty(certificateTokens));
	}
	
	@Test
	public void ldapUrl() throws Exception {
		String url = "ldap://crl-source.hn/o=Hello";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Exception exception = assertThrows(UnsupportedOperationException.class, () -> sslCertificateDataLoader.getCertificates(url));
		assertEquals("DSS framework supports only HTTP(S) certificate extraction. Obtained URL : 'ldap://crl-source.hn/o=Hello'", exception.getMessage());
	}
	
	@Test
	public void emptyUrl() throws Exception {
		String url = " ";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Exception exception = assertThrows(UnsupportedOperationException.class, () -> sslCertificateDataLoader.getCertificates(url));
		assertEquals("DSS framework supports only HTTP(S) certificate extraction. Obtained URL : ' '", exception.getMessage());
	}

}
