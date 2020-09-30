package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class ITextProtectedDocumentTest extends AbstractPAdESTestValidation {
	
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
		
		assertThrows(ProtectedDocumentException.class, () -> sign(openProtected, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedNone, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedNoField, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedWithField, correctProtectionPhrase));
		
	}
	
	@Test
	public void extendSignatureTest() throws Exception {
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		
		assertThrows(ProtectedDocumentException.class, () -> service.extendDocument(openProtected, signatureParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.extendDocument(editionProtectedNone, signatureParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.extendDocument(editionProtectedSigningAllowedNoField, signatureParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.extendDocument(editionProtectedSigningAllowedWithField, signatureParameters));
		
	}
	
	@Test
	public void addSignatureFieldTest() throws Exception {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		
		DSSDocument document = openProtected;
		
		List<String> signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(0, signatureFields.size());
		
		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setPage(0);
		signatureFieldParameters.setFieldId("SignatureField1");
		assertThrows(ProtectedDocumentException.class, () -> service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase));
	}

	private DSSDocument sign(DSSDocument doc, String pwd) throws Exception {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(
				getOfflineCertificateVerifier());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setPasswordProtection(pwd);

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
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
