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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class SSLCommonDataLoaderTest {

	private static final String URL = "https://ec.europa.eu/cefdigital/eSignature";

	private static final String SSL_CERT = "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";
	private static final String WRONG_CERT = "MIIFvjCCA6agAwIBAgIQALwvYx2O1YN6UxQOi3Bx3jANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFUzEoMCYGA1UECgwfRElSRUNDSU9OIEdFTkVSQUwgREUgTEEgUE9MSUNJQTEMMAoGA1UECwwDQ05QMRQwEgYDVQQDDAtBQyBSQUlaIERHUDAeFw0wNzAxMjUxMjA1MDhaFw0zNzAxMjUxMjA1MDhaMFsxCzAJBgNVBAYTAkVTMSgwJgYDVQQKDB9ESVJFQ0NJT04gR0VORVJBTCBERSBMQSBQT0xJQ0lBMQwwCgYDVQQLDANDTlAxFDASBgNVBAMMC0FDIFJBSVogREdQMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBD1t16zMJxvoxuIDlyt6pfgzPmmfJMFvPyoj0AOxjyxu6f77K/thV/pMatQqjGae3Yj83upv7YFygq/jU02EeEIeQQEf+QJ+B+LX+oGLPbU5g8/W1eFcnXC4Jg2ipP7L2qcEfA180AsT1UqmHTc7kRI3N6yJZZiHkM4hpjf3vgsCxUQtXw+XAZYtaRbjFO69tTSdbpbXN4fvOQwHNlenF1GMxsih7tgGUwRlY2EVfh7EGYvXt2mtpHiEIeSp1s2WBxzgiWU1IufiDo18olZj859oHkNBD0sx6LVPPun/sINuM1M6aBRwc725cMgZmIyNDOHZkqExL8DNUiTzXYzqr7R/X+kn59RYLwIEmfRQLkKxyYlZeFbuOI5n7Uz3vKANcTbUuCymA0+ZA9ESlrz8kA6fHV0+fMePUBYnociJO5fFX/jxtScOqrQt+K+gGm4TubalBoL7ECGzs3CmKtnuyOH+KFO/8q71Fxhn3WqlKgO7dBUhp0I/7dr4R2bF4ry1NnqZWObCuBfKqyL80Dx+6zaGsTo7UBLNdcA4sXArJoAMUqHb/77rqu45dWJIhQA5V3qolwowwuTdZwC1ec2AWwA6gMf2uchNJsPWWmQrkXvkhu2rI756cKwgR7y22517q/B9MNx7InsZbMbOWUwQuei3UcoIgCFs2TWCbhxHNkCAwEAAaN+MHwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA6cduGiLokzQfLjPmxbFkW9vYaOMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUFBwIBFhlodHRwOi8vd3d3LnBvbGljaWEuZXMvZHBjMA0GCSqGSIb3DQEBBQUAA4ICAQBslvw3pwCj21vCctyL7YOrmfINjJFp4TNFfNnDwSsuonqOjwppXCEFJ6MkOeCUOy9vXziNoYtoDd/tXAn++9975d7PB9vXnu7ErHRx+e74obKpqfBoVv9fwPp0bObO3YbTq9EGPLM8mbcUEivPlL2mQ7tk78z2p8gpytcCZRc08Jd5m+AeYPrHUDeF6ZIlnH7SIrtP3Bp8zwnNIFbNtkyrCyWtN8Ajo3RXqecM/bs+YgGzjVbDToQUBkBCuoG3XU+QYSQ79yZsvjTCsFKBYnXXijiGZSokx33iauY0PIyaNu/ulMloSNUwWZ5WBPqJXWlkZ+deApxZLXJLFMSTjFeFdpZUgOC1wrRkxXidWQwr4566fYWhYH0w+hwK9gD6NEsMA3D7NOPCTCOx9Qst5848RsJVJ4F+ZFmT4iyTYLyglkNkeB+tSXVyC9Lg+Tvay85VyeZMSZ3PpGmpNzaQxVZl9XCfs8R6Ew4pG91eOA0BjsI1ZHY7H9e5Pomup/jTA6JwlCYooEiBM31Gdwe/3oUFNzB+NvOWdwb+ZG6va70j98EdipGWoLvjv/oJlFN2q1Nrt/u7whKp+VsVOjuZMrSpw9C+Ec4yiLha5RRiXnHX1cqwT694KIDQZIgqQChQDeDqrvCphtdHdxFQ5NBzt2HKhaSh8ggDdOdpH451rB45Jg==";

	private static final String KS_TYPE = "PKCS12";
	private static final String CORRECT_KS_PATH = "target/ks.p12";
	private static final String WRONG_KS_PATH = "target/wrong.p12";

	@BeforeAll
	public static void initKS() {
		CertificateToken sslCert = DSSUtils.loadCertificateFromBase64EncodedString(SSL_CERT);

		try (OutputStream os = new FileOutputStream(CORRECT_KS_PATH)) {
			KeyStore ks = KeyStore.getInstance(KS_TYPE);
			ks.load(null);
			ks.setCertificateEntry("cef", sslCert.getCertificate());
			ks.store(os, new char[] { 'a', 'z', 'e', 'r', 't' });
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		CertificateToken wrongCert = DSSUtils.loadCertificateFromBase64EncodedString(WRONG_CERT);

		try (OutputStream os = new FileOutputStream(WRONG_KS_PATH)) {
			KeyStore ks = KeyStore.getInstance(KS_TYPE);
			ks.load(null);
			ks.setCertificateEntry("cef", wrongCert.getCertificate());
			ks.store(os, new char[] { 'a', 'z', 'e', 'r', 't' });
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void testDefault() {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		byte[] binaries = dataLoader.get(URL);
		assertNotNull(binaries);
		assertTrue(binaries.length > 0);
	}

	@Test
	public void testTrustStore() throws GeneralSecurityException, IOException {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setSslTruststorePath(CORRECT_KS_PATH);
		dataLoader.setSslTruststoreType(KS_TYPE);
		dataLoader.setSslTruststorePassword("azert");

		byte[] binaries = dataLoader.get(URL);
		assertNotNull(binaries);
		assertTrue(binaries.length > 0);
	}

	@Test
	// TODO check root cause SSLHandshakeException
	public void testWrongTrustStore() throws GeneralSecurityException, IOException {
		Exception exception = assertThrows(DSSException.class, () -> {
			CommonsDataLoader dataLoader = new CommonsDataLoader();
			dataLoader.setSslTruststorePath(WRONG_KS_PATH);
			dataLoader.setSslTruststoreType(KS_TYPE);
			dataLoader.setSslTruststorePassword("azert");

			dataLoader.setSslKeystorePath(WRONG_KS_PATH);
			dataLoader.setSslKeystoreType(KS_TYPE);
			dataLoader.setSslKeystorePassword("azert");

			byte[] binaries = dataLoader.get(URL);
			assertNotNull(binaries);
			assertTrue(binaries.length > 0);
		});
		assertEquals("Unable to process GET call for url 'https://ec.europa.eu/cefdigital/eSignature'", exception.getMessage());
	}

}
