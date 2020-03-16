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
package eu.europa.esig.dss.spi.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.RepeatedTest;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class CertificatePoolMultiThreadTest {

	public CertificatePoolMultiThreadTest() {
	}

	@RepeatedTest(5)
	public void testMultiThreads() throws IOException {

		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/extract-tls.p12"), "PKCS12", "ks-password");
		List<CertificateToken> certificates = kscs.getCertificates();

		CertificatePool sharedPool = new CertificatePool();

		ExecutorService executor = Executors.newFixedThreadPool(20);

		List<Future<Integer>> futures = new ArrayList<>();

		for (int i = 0; i < 100; i++) {
			futures.add(executor.submit(new TestConcurrent(sharedPool, certificates)));

			// not shared
			futures.add(executor.submit(new TestConcurrent(new CertificatePool(), certificates)));
		}

		for (Future<Integer> future : futures) {
			try {
				assertEquals(2438, future.get().intValue());
			} catch (Exception e) {
				fail(e.getMessage());
			}
		}

		executor.shutdown();

	}

	class TestConcurrent implements Callable<Integer> {

		private final CertificatePool sharedPool;
		private final List<CertificateToken> certificates;

		public TestConcurrent(CertificatePool sharedPool, List<CertificateToken> certificates) {
			this.sharedPool = sharedPool;
			this.certificates = certificates;
		}

		@Override
		public Integer call() throws Exception {

			for (CertificateToken certificateToken : certificates) {
				for (CertificateSourceType source : CertificateSourceType.values()) {
					sharedPool.getInstance(certificateToken, source);
				}
			}

			for (CertificateToken certificateToken : certificates) {
				assertTrue(sharedPool.isTrusted(certificateToken), "Certificate should be trusted");
				assertFalse(sharedPool.getSources(certificateToken).isEmpty(), "Sources for certificate shouldn't be empty");
				assertFalse(sharedPool.get(certificateToken.getSubject()).isEmpty(), "Certificate by subject shoudln't be empty");
			}

			return sharedPool.getNumberOfCertificates();
		}

	}

}
