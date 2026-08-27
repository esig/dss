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
package plugtests;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import static java.time.Duration.ofSeconds;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
class SignaturePoolTest extends AbstractTestSignaturePool {
	
	private static final Logger LOG = LoggerFactory.getLogger(SignaturePoolTest.class);

	private static DSSDocument document;

	private static Stream<Arguments> data() {

		// -Dsignature.pool.folder=...

		String signaturePoolFolder = System.getProperty("signature.pool.folder", "src/test/resources/signature-pool");
		File folder = new File(signaturePoolFolder);
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "asice", "asics", "bdoc", "csig", "ddoc",
				"ers", "es3", "json", "p7", "p7b", "p7m", "p7s", "pdf", "pkcs7", "sce", "scs", "xml", "xsig" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			if(!(file.getPath().toLowerCase().contains("attestation-pool"))) {
				dataToRun.add(Arguments.of(file));
			}
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	void testValidate(File fileToTest) {
		LOG.info("Begin : {}", fileToTest.getAbsolutePath());
		document = new FileDocument(fileToTest);
		try {
			assertTimeout(ofSeconds(3L), super::validate, "Execution exceeded timeout for file " + fileToTest);
			LOG.info("End : {}", fileToTest.getAbsolutePath());
		} catch (Exception e) {
			fail("Validation of " + fileToTest + " failed", e);
		}
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);

		validator.setCertificateVerifier(certificateVerifier());
		
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setDataLoader(null);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		
		return validator;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}

}