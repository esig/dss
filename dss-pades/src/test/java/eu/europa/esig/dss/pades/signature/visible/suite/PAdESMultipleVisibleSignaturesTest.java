package eu.europa.esig.dss.pades.signature.visible.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESMultipleVisibleSignaturesTest extends AbstractPAdESTestValidation {
	
	private static DSSDocument image;

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		image = new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);
	}
	
	@Test
	public void signatureOverlapTest() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		
		imageParameters.setImage(image);
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setWidth(100);
		imageParameters.setHeight(100);
		documentToSign = signAndValidate();

		imageParameters.setxAxis(150);
		imageParameters.setyAxis(150);
		Exception exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		imageParameters.setxAxis(300);
		imageParameters.setyAxis(100);
		documentToSign = signAndValidate();
		assertNotNull(documentToSign);
	}
	
	@Test
	public void signatureAndTimestampOverlapTest() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		
		imageParameters.setImage(image);
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setWidth(100);
		imageParameters.setHeight(100);
		documentToSign = signAndValidate();
		
		SignatureImageParameters timestampImageParameters = new SignatureImageParameters();
		timestampImageParameters.setxAxis(150);
		timestampImageParameters.setyAxis(100);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Timestamp");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		timestampImageParameters.setTextParameters(textParameters);
		
		PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
		timestampParameters.setImageParameters(timestampImageParameters);

		Exception exception = assertThrows(AlertException.class, () -> service.timestamp(documentToSign, timestampParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		timestampImageParameters.setxAxis(300);
		documentToSign = service.timestamp(documentToSign, timestampParameters);
		
		Reports reports = verify(documentToSign);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
		
		// new signature over a timestamp
		imageParameters.setxAxis(350);
		exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}
	
	@Test
	public void signOverEmptySignatureFieldTest() throws IOException {
		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setOriginX(100);
		signatureFieldParameters.setOriginY(100);
		signatureFieldParameters.setWidth(100);
		signatureFieldParameters.setHeight(100);
		signatureFieldParameters.setName("signature1");
		
		documentToSign = service.addNewSignatureField(documentToSign, signatureFieldParameters);
		
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		
		imageParameters.setImage(image);
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setWidth(100);
		imageParameters.setHeight(100);
		Exception exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		signatureParameters.setSignatureFieldId("signature1");
		DSSDocument signed = signAndValidate();
		assertNotNull(signed);
	}
	
	private DSSDocument signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		verify(signedDocument);
		return signedDocument;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
