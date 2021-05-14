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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test DSS with multi threads
 * 
 */
public class ConcurrentValidationTest {

	private static final Logger LOG = LoggerFactory.getLogger(ConcurrentValidationTest.class);

	@Test
	public void test() {

		ExecutorService executor = Executors.newFixedThreadPool(20);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(new DefaultAIASource());

		List<Future<Boolean>> futures = new ArrayList<>();

		for (int i = 0; i < 200; i++) {
			futures.add(executor.submit(new TestConcurrent(certificateVerifier)));
		}

		for (Future<Boolean> future : futures) {
			try {
				assertTrue(future.get());
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}

		executor.shutdown();
	}

	class TestConcurrent implements Callable<Boolean> {

		private final CommonCertificateVerifier certificateVerifier;

		public TestConcurrent(CommonCertificateVerifier certificateVerifier) {
			this.certificateVerifier = certificateVerifier;
		}

		@Override
		public Boolean call() throws Exception {
			DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
			validator.setCertificateVerifier(certificateVerifier);

			return validator.validateDocument() != null;
		}

	}

}
