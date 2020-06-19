package eu.europa.esig.dss.pades.signature;

import java.security.SecureRandom;

import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SerializableParameters;
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

public class PdfBoxSignEncryptedWithCustomFixedSecureRandomTest extends AbstractPAdESTestSignature {
	
	private static final String PASSWORD = " ";

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeType.PDF);

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
	
	private class MockFixedSecureRandomProvider implements SecureRandomProvider {
		
		private final byte[] seed;
		
		public MockFixedSecureRandomProvider(byte[] seed) {
			this.seed = seed;
		}

		@Override
		public SecureRandom getSecureRandom() {
			return new FixedSecureRandom(seed);
		}

		@Override
		public void setParameters(SerializableParameters parameters) {
			// do nothing
		}
		
	}
	
	private class MockPdfBoxDefaultObjectFactory extends PdfBoxDefaultObjectFactory {
		
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
