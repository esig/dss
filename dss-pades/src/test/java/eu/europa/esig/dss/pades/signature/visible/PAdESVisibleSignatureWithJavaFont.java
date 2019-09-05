package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESVisibleSignatureWithJavaFont extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
	}

	@Test
	public void testJavaFont() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setFont(new DSSJavaFont(new Font(Font.SERIF, Font.BOLD, 28)));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate("testJavaFont");
	}

	@Test
	public void testFontByFamilyName() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setFont(new DSSJavaFont(Font.SERIF));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate("testFontByFamilyName");
	}

	@Test
	public void testFontByFamilyNameAndSize() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setFont(new DSSJavaFont(Font.SERIF, 15));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate("testFontByFamilyNameAndSize");
	}

	@Test
	public void testFontAllValues() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GRAY);
		textParameters.setFont(new DSSJavaFont(Font.MONOSPACED, Font.ITALIC, 16));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate("testFontAllValues");
	}

	@Test
	public void testFontBoldAndItalic() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.RED);
		Font font = new Font(Font.SANS_SERIF, Font.BOLD + Font.ITALIC, 14);
		textParameters.setFont(new DSSJavaFont(font));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);

		signAndValidate("testFontBoldAndItalic");
	}

	private void signAndValidate(String fileName) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		signedDocument.save("target/" + fileName + ".pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
