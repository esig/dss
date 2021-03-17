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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class SSLCommonDataLoaderTest {

	private static final String URL = "https://github.com/esig/dss";

	private static final String WRONG_CERT = "MIIFvjCCA6agAwIBAgIQALwvYx2O1YN6UxQOi3Bx3jANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFUzEoMCYGA1UECgwfRElSRUNDSU9OIEdFTkVSQUwgREUgTEEgUE9MSUNJQTEMMAoGA1UECwwDQ05QMRQwEgYDVQQDDAtBQyBSQUlaIERHUDAeFw0wNzAxMjUxMjA1MDhaFw0zNzAxMjUxMjA1MDhaMFsxCzAJBgNVBAYTAkVTMSgwJgYDVQQKDB9ESVJFQ0NJT04gR0VORVJBTCBERSBMQSBQT0xJQ0lBMQwwCgYDVQQLDANDTlAxFDASBgNVBAMMC0FDIFJBSVogREdQMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBD1t16zMJxvoxuIDlyt6pfgzPmmfJMFvPyoj0AOxjyxu6f77K/thV/pMatQqjGae3Yj83upv7YFygq/jU02EeEIeQQEf+QJ+B+LX+oGLPbU5g8/W1eFcnXC4Jg2ipP7L2qcEfA180AsT1UqmHTc7kRI3N6yJZZiHkM4hpjf3vgsCxUQtXw+XAZYtaRbjFO69tTSdbpbXN4fvOQwHNlenF1GMxsih7tgGUwRlY2EVfh7EGYvXt2mtpHiEIeSp1s2WBxzgiWU1IufiDo18olZj859oHkNBD0sx6LVPPun/sINuM1M6aBRwc725cMgZmIyNDOHZkqExL8DNUiTzXYzqr7R/X+kn59RYLwIEmfRQLkKxyYlZeFbuOI5n7Uz3vKANcTbUuCymA0+ZA9ESlrz8kA6fHV0+fMePUBYnociJO5fFX/jxtScOqrQt+K+gGm4TubalBoL7ECGzs3CmKtnuyOH+KFO/8q71Fxhn3WqlKgO7dBUhp0I/7dr4R2bF4ry1NnqZWObCuBfKqyL80Dx+6zaGsTo7UBLNdcA4sXArJoAMUqHb/77rqu45dWJIhQA5V3qolwowwuTdZwC1ec2AWwA6gMf2uchNJsPWWmQrkXvkhu2rI756cKwgR7y22517q/B9MNx7InsZbMbOWUwQuei3UcoIgCFs2TWCbhxHNkCAwEAAaN+MHwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA6cduGiLokzQfLjPmxbFkW9vYaOMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUFBwIBFhlodHRwOi8vd3d3LnBvbGljaWEuZXMvZHBjMA0GCSqGSIb3DQEBBQUAA4ICAQBslvw3pwCj21vCctyL7YOrmfINjJFp4TNFfNnDwSsuonqOjwppXCEFJ6MkOeCUOy9vXziNoYtoDd/tXAn++9975d7PB9vXnu7ErHRx+e74obKpqfBoVv9fwPp0bObO3YbTq9EGPLM8mbcUEivPlL2mQ7tk78z2p8gpytcCZRc08Jd5m+AeYPrHUDeF6ZIlnH7SIrtP3Bp8zwnNIFbNtkyrCyWtN8Ajo3RXqecM/bs+YgGzjVbDToQUBkBCuoG3XU+QYSQ79yZsvjTCsFKBYnXXijiGZSokx33iauY0PIyaNu/ulMloSNUwWZ5WBPqJXWlkZ+deApxZLXJLFMSTjFeFdpZUgOC1wrRkxXidWQwr4566fYWhYH0w+hwK9gD6NEsMA3D7NOPCTCOx9Qst5848RsJVJ4F+ZFmT4iyTYLyglkNkeB+tSXVyC9Lg+Tvay85VyeZMSZ3PpGmpNzaQxVZl9XCfs8R6Ew4pG91eOA0BjsI1ZHY7H9e5Pomup/jTA6JwlCYooEiBM31Gdwe/3oUFNzB+NvOWdwb+ZG6va70j98EdipGWoLvjv/oJlFN2q1Nrt/u7whKp+VsVOjuZMrSpw9C+Ec4yiLha5RRiXnHX1cqwT694KIDQZIgqQChQDeDqrvCphtdHdxFQ5NBzt2HKhaSh8ggDdOdpH451rB45Jg==";

	private static final String KS_TYPE = "PKCS12";
	private static final String CORRECT_KS_PATH = "target/ks.p12";
	private static final String WRONG_KS_PATH = "target/wrong.p12";
	private static final char[] KS_PASSWORD = new char[] { 'a', 'z', 'e', 'r', 't' };
	
	private static DSSDocument correctKeyStore;
	private static DSSDocument wrongKeyStore;

	@BeforeAll
	public static void initKS() {
		// load signing certificate automatically, in order to resolve SSL cert update issue
		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		List<CertificateToken> certificateTokens = sslCertificateDataLoader.getCertificates(URL);
		assertTrue(Utils.isCollectionNotEmpty(certificateTokens));

		try (OutputStream os = new FileOutputStream(CORRECT_KS_PATH)) {
			KeyStore ks = KeyStore.getInstance(KS_TYPE);
			ks.load(null);
			ks.setCertificateEntry("cef", certificateTokens.iterator().next().getCertificate());
			ks.store(os, KS_PASSWORD);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		correctKeyStore = new FileDocument(CORRECT_KS_PATH);

		CertificateToken wrongCert = DSSUtils.loadCertificateFromBase64EncodedString(WRONG_CERT);

		try (OutputStream os = new FileOutputStream(WRONG_KS_PATH)) {
			KeyStore ks = KeyStore.getInstance(KS_TYPE);
			ks.load(null);
			ks.setCertificateEntry("cef", wrongCert.getCertificate());
			ks.store(os, KS_PASSWORD);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		wrongKeyStore = new FileDocument(WRONG_KS_PATH);
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
		dataLoader.setSslTruststore(correctKeyStore);
		dataLoader.setSslTruststoreType(KS_TYPE);
		dataLoader.setSslTruststorePassword(new String(KS_PASSWORD));

		byte[] binaries = dataLoader.get(URL);
		assertNotNull(binaries);
		assertTrue(binaries.length > 0);
	}

	@Test
	// TODO check root cause SSLHandshakeException
	public void testWrongTrustStore() throws GeneralSecurityException, IOException {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setSslTruststore(wrongKeyStore);
		dataLoader.setSslTruststoreType(KS_TYPE);
		dataLoader.setSslTruststorePassword(new String(KS_PASSWORD));

		dataLoader.setSslTruststore(wrongKeyStore);
		dataLoader.setSslKeystoreType(KS_TYPE);
		dataLoader.setSslKeystorePassword(new String(KS_PASSWORD));

		Exception exception = assertThrows(DSSException.class, () -> dataLoader.get(URL));
		assertTrue(exception.getMessage().contains("Unable to process GET call for url [" + URL + "]"));
	}

}
