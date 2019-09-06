package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.spi.x509.CertificatePool;

public class PdfSignatureServiceTest {
	
	private MockPdfSignatureSignature mockPDFSignatureSignature;
	
	@BeforeEach
	public void init() {
		mockPDFSignatureSignature = new MockPdfSignatureSignature(false, null);
	}
	
	@Test
	public void validateByteRangeTest() {
		assertTrue(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 2400, 480}));
		
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 1, 1280, 2400, 480}));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 0, 240, 480}));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 240, 480}));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 2400, 0}));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[0]));
	}
	
	protected class MockPdfSignatureSignature extends AbstractPDFSignatureService {

		protected MockPdfSignatureSignature(boolean timestamp, SignatureDrawerFactory signatureDrawerFactory) {
			super(timestamp, signatureDrawerFactory);
		}

		@Override
		public byte[] digest(DSSDocument toSignDocument, PAdESSignatureParameters parameters,
				DigestAlgorithm digestAlgorithm) {
			return null;
		}

		@Override
		public DSSDocument sign(DSSDocument pdfData, byte[] signatureValue, PAdESSignatureParameters parameters,
				DigestAlgorithm digestAlgorithm) {
			return null;
		}

		@Override
		public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) {
			return null;
		}

		@Override
		public List<String> getAvailableSignatureFields(DSSDocument document) {
			return null;
		}

		@Override
		public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
			return null;
		}

		@Override
		protected List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool,
				DSSDocument document) {
			return null;
		}
		
		protected boolean isByteRangeCorrect(int[] byteRange) {
			try {
				validateByteRange(byteRange);
				return true;
			} catch (DSSException e) {
				return false;
			}
		}
		
	}

}
