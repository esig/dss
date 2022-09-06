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
package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.encryption.SecureRandomProvider;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.jupiter.api.BeforeEach;

import java.security.SecureRandom;

public class PdfBoxSignEncryptedWithCustomFixedSecureRandomTest extends AbstractPAdESTestSignature {
	
	private static final String PASSWORD = " ";

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeTypeEnum.PDF);

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		
		signatureParameters.setPasswordProtection(PASSWORD);

		service = new PAdESService(getOfflineCertificateVerifier());
		
		MockPdfBoxDefaultObjectFactory mockPdfBoxDefaultObjectFactory = new MockPdfBoxDefaultObjectFactory();
		service.setPdfObjFactory(mockPdfBoxDefaultObjectFactory);
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
		validator.setPasswordProtection(PASSWORD);
		return validator;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	private static class MockFixedSecureRandomProvider implements SecureRandomProvider {
		
		private final byte[] seed;
		
		public MockFixedSecureRandomProvider(byte[] seed) {
			this.seed = seed;
		}

		@Override
		public SecureRandom getSecureRandom() {
			return new FixedSecureRandom(seed);
		}
		
	}
	
	private static class MockPdfBoxDefaultObjectFactory extends PdfBoxDefaultObjectFactory {
		
		private SecureRandomProvider secureRandomProvider;
		
		private SecureRandomProvider getSecureRandomProvider() {
			if (secureRandomProvider == null) {
				byte[] seed = DSSUtils.digest(DigestAlgorithm.SHA512, "Random seed value".getBytes());
				secureRandomProvider = new MockFixedSecureRandomProvider(seed);
			}
			return secureRandomProvider;
		}

		@Override
		public PDFSignatureService newPAdESSignatureService() {
			PdfBoxSignatureService padesSignatureService = (PdfBoxSignatureService) super.newPAdESSignatureService();
			padesSignatureService.setSecureRandomProvider(getSecureRandomProvider());
			return padesSignatureService;
		}

		@Override
		public PDFSignatureService newContentTimestampService() {
			PdfBoxSignatureService padesSignatureService = (PdfBoxSignatureService) super.newContentTimestampService();
			padesSignatureService.setSecureRandomProvider(getSecureRandomProvider());
			return padesSignatureService;
		}

		@Override
		public PDFSignatureService newSignatureTimestampService() {
			PdfBoxSignatureService padesSignatureService = (PdfBoxSignatureService) super.newSignatureTimestampService();
			padesSignatureService.setSecureRandomProvider(getSecureRandomProvider());
			return padesSignatureService;
		}

		@Override
		public PDFSignatureService newArchiveTimestampService() {
			PdfBoxSignatureService padesSignatureService = (PdfBoxSignatureService) super.newArchiveTimestampService();
			padesSignatureService.setSecureRandomProvider(getSecureRandomProvider());
			return padesSignatureService;
		}
		
	}

}
