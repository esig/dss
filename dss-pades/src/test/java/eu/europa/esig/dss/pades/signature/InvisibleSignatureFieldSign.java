package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class InvisibleSignatureFieldSign extends PKIFactoryAccess {

	private static final String SIG_FIELD = "Signature1";

	private static final DSSDocument DOC = new InMemoryDocument(
			InvisibleSignatureFieldSign.class.getResourceAsStream("/unsignedPDFWithSignatureFieldButInvisible.pdf"));

	@Test
	public void getAvailableSignatureFields() {
		List<String> availableSignatureFields = getAvailableSignatureFields(DOC);
		assertEquals(1, availableSignatureFields.size());
		assertTrue(availableSignatureFields.contains(SIG_FIELD));
	}

	private List<String> getAvailableSignatureFields(DSSDocument doc) {
		PAdESService service = new PAdESService(new CommonCertificateVerifier());
		return service.getAvailableSignatureFields(doc);
	}

	@Test
	public void sign() throws IOException {

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
		parameters.setSignatureFieldId(SIG_FIELD);

		ToBeSigned dataToSign = service.getDataToSign(DOC, parameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(DOC, parameters, signatureValue);

//		signedDocument.save("target/doc.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA.toString(), diagnosticData.getFirstSignatureFormat());

//		TODO investigate with OpenPDF
//		List<String> availableSignatureFields = getAvailableSignatureFields(signedDocument);
//		assertEquals(0, availableSignatureFields.size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
