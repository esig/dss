package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PdfBoxProtectedDocumentTest extends AbstractPAdESTestValidation {

	private final String correctProtectionPhrase = " ";

	private final DSSDocument openProtected = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeType.PDF);

	private final DSSDocument editionProtectedNone = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_none.pdf"), "sample.pdf", MimeType.PDF);

	private final DSSDocument editionProtectedSigningAllowedNoField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"), "sample.pdf",
			MimeType.PDF);

	private final DSSDocument editionProtectedSigningAllowedWithField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_with_field.pdf"), "sample.pdf",
			MimeType.PDF);

	@Test
	public void signatureOperationsCorrectPassword() throws Exception {
		DSSDocument document = null;

		document = sign(openProtected, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedNone, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedSigningAllowedNoField, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedSigningAllowedWithField, correctProtectionPhrase);
		verify(document);
	}
	
	@Test
	public void ltaSigningTest() throws Exception {
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());
		
		PAdESSignatureParameters signatureParameters = getParameters();
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		DSSDocument signed = sign(padesService, openProtected, signatureParameters);
		verify(signed);
	} 
	
	@Test
	public void recreateParamsTest() throws Exception {
		Date date = new Date();
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());
		
		PAdESSignatureParameters parametersDataToBeSigned = getParameters();
		parametersDataToBeSigned.bLevel().setSigningDate(date);
		parametersDataToBeSigned.setPasswordProtection(correctProtectionPhrase);
		parametersDataToBeSigned.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		ToBeSigned dataToSign = padesService.getDataToSign(openProtected, parametersDataToBeSigned);

		PAdESSignatureParameters parametersSignatureValue = getParameters();
		parametersSignatureValue.bLevel().setSigningDate(date);
		parametersSignatureValue.setPasswordProtection(correctProtectionPhrase);
		parametersSignatureValue.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		SignatureValue signatureValue = getToken().sign(dataToSign, parametersSignatureValue.getDigestAlgorithm(), getPrivateKeyEntry());

		PAdESSignatureParameters parametersSign = getParameters();
		parametersSign.bLevel().setSigningDate(date);
		parametersSign.setPasswordProtection(correctProtectionPhrase);
		parametersSign.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		DSSDocument signedDocument = padesService.signDocument(openProtected, parametersSign, signatureValue);
		
		PDFDocumentValidator validator = (PDFDocumentValidator) getValidator(signedDocument);
		validator.setPasswordProtection(correctProtectionPhrase);
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		checkBLevelValid(diagnosticData);
		checkTimestamps(diagnosticData);
	}
	
	@Test
	public void extendOperationsTest() throws Exception {
		DSSDocument signedDoc = sign(openProtected, correctProtectionPhrase);
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		
		DSSDocument extendedDoc = service.extendDocument(signedDoc, signatureParameters);
		
		Reports reports = verify(extendedDoc);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Test
	public void addSignatureFieldTest() throws Exception {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		
		DSSDocument document = openProtected;
		
		List<String> signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(0, signatureFields.size());
		
		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setPage(0);
		String firstFieldName = "SignatureField1";
		signatureFieldParameters.setName(firstFieldName);
		document = service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase);
		
		signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(1, signatureFields.size());

		String secondFieldName = "SignatureField2";
		signatureFieldParameters.setName(secondFieldName);
		document = service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase);
		
		signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(2, signatureFields.size());
		assertTrue(signatureFields.contains(firstFieldName));
		assertTrue(signatureFields.contains(secondFieldName));
		
		// sign
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		signatureParameters.setSignatureFieldId(firstFieldName);
		
		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		
		Reports reports = verify(signedDocument);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(firstFieldName, signature.getFirstFieldName());
		
		signatureFields = service.getAvailableSignatureFields(signedDocument, correctProtectionPhrase);
		assertEquals(1, signatureFields.size());
	}

	private DSSDocument sign(DSSDocument doc, String pwd) throws Exception {
		PAdESService service = new PAdESService(getOfflineCertificateVerifier());

		PAdESSignatureParameters signatureParameters = getParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setPasswordProtection(pwd);

		return sign(service, doc, signatureParameters);
	}
	
	private PAdESSignatureParameters getParameters() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		return signatureParameters;
	}
	
	private DSSDocument sign(PAdESService service, DSSDocument doc, PAdESSignatureParameters signatureParameters) throws Exception {
		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
		validator.setPasswordProtection(correctProtectionPhrase);
		return validator;
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

}
