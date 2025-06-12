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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.junit.jupiter.api.RepeatedTest;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

class CertificateSourceMultiThreadTest {

	@RepeatedTest(5)
	void testMultiThreads() throws IOException {

		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/extract-tls.p12"), "PKCS12", "ks-password".toCharArray());
		List<CertificateToken> certificates = kscs.getCertificates();

		CommonCertificateSource sharedCertSource = new CommonCertificateSource();

		ExecutorService executor = Executors.newFixedThreadPool(20);

		List<Future<Integer>> futures = new ArrayList<>();

		for (int i = 0; i < 100; i++) {
			futures.add(executor.submit(new TestConcurrent(sharedCertSource, certificates)));

			// not shared
			futures.add(executor.submit(new TestConcurrent(new CommonCertificateSource(), certificates)));
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

	private static class TestConcurrent implements Callable<Integer> {

		private final CommonCertificateSource sharedCertSource;
		private final List<CertificateToken> certificates;

		public TestConcurrent(CommonCertificateSource sharedCertSource, List<CertificateToken> certificates) {
			this.sharedCertSource = sharedCertSource;
			this.certificates = certificates;
		}

		@Override
		public Integer call() throws Exception {

			for (CertificateToken certificateToken : certificates) {
				sharedCertSource.addCertificate(certificateToken);
			}

			for (CertificateToken certificateToken : certificates) {
				assertFalse(sharedCertSource.isTrusted(certificateToken), "Certificate should not be trusted");
				assertFalse(sharedCertSource.getBySubject(certificateToken.getSubject()).isEmpty(), "Certificate by subject shouldn't be empty");
				assertFalse(sharedCertSource.getByPublicKey(certificateToken.getPublicKey()).isEmpty(), "Certificate by public key shouldn't be empty");
				assertFalse(sharedCertSource.getByEntityKey(certificateToken.getEntityKey()).isEmpty(), "Certificate by entity key shouldn't be empty");
			}

			return sharedCertSource.getNumberOfCertificates();
		}

	}

}
