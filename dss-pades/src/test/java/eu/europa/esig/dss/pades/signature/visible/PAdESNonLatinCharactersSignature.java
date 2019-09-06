package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class PAdESNonLatinCharactersSignature extends AbstractPAdESTestSignature {

	private PAdESService padesService;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.setLocation("Люксембург");
		signatureParameters.setReason("DSS ხელმოწერა");
		signatureParameters.setContactInfo("Jira");
		signatureParameters.setSignatureFieldId("подпись1");

		SignatureFieldParameters parameters = new SignatureFieldParameters();
		parameters.setName("подпись1");
		parameters.setOriginX(10);
		parameters.setOriginY(10);
		parameters.setHeight(150);
		parameters.setWidth(150);
		
		padesService = new PAdESService(getCompleteCertificateVerifier());
		documentToSign = padesService.addNewSignatureField(documentToSign, parameters);
		
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Моя подпись 1");
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(signatureImageParameters);

		padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());
	}
	
	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals("подпись1", signature.getSignatureFieldName());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters> getService() {
		return padesService;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}
	
}
