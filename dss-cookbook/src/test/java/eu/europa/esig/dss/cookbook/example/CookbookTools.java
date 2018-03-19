package eu.europa.esig.dss.cookbook.example;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public class CookbookTools extends PKIFactoryAccess {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

	/**
	 * The document to extend
	 */
	static protected DSSDocument toExtendDocument;

	/**
	 * This method sets the common parameters.
	 */
	protected static void prepareXmlDoc() {
		toSignDocument = new FileDocument(new File("src/main/resources/xml_example.xml"));
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePdfDoc() {
		toSignDocument = new FileDocument(new File("src/main/resources/hello-world.pdf"));
	}

	/**
	 * This method creates a new instance of PKCS12 keystore
	 * 
	 */
	protected static Pkcs12SignatureToken getPkcs12Token() throws IOException {
		return new Pkcs12SignatureToken("src/main/resources/user_a_rsa.p12", new PasswordProtection("password".toCharArray()));
	}

	protected void testFinalDocument(DSSDocument signedDocument) {
		assertNotNull(signedDocument);
		assertNotNull(DSSUtils.toByteArray(signedDocument));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected TSPSource getOnlineTSPSource() {
		return getGoodTsa();
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
