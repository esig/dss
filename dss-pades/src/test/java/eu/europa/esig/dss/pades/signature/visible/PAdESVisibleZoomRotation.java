package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureRotation;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;


public class PAdESVisibleZoomRotation extends PKIFactoryAccess {

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
	public void testNoTransformations() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testZoomOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		
		imageParameters.setZoom(200);
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testRotationOnly() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		signAndValidate();
	}
	
	@Test
	public void testZoomAndRotation() throws Exception {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getRedBox());
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		
		imageParameters.setZoom(200);
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		signAndValidate();
	}

	private void signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// signedDocument.save("target/test.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	private DSSDocument getRedBox() {
		return new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
