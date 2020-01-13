package eu.europa.esig.dss.asic.xades.signature.opendocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Date;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class OpenDocumentSignLTALevelTest extends OpenDocumentLevelLTASignatureTest {

	public OpenDocumentSignLTALevelTest(File fileToTest) {
		super(fileToTest);
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		DSSDocument signedDocument = new InMemoryDocument(byteArray);
		
		DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service = getService();
		ASiCWithXAdESSignatureParameters signatureParameters = getSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		
		ToBeSigned dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		assertEquals(2, diagnosticData.getSignatures().size());
		assertEquals(4, diagnosticData.getTimestampList().size());

		boolean archiveTimestampFound = false;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestampFound = true;
			}
		}
		assertTrue(archiveTimestampFound);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isBLevelTechnicallyValid());
			assertTrue(signature.isSignatureValid());
			assertTrue(signature.isSignatureIntact());
			for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
		}
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		// disable check
	}

}
