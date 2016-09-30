package eu.europa.esig.dss.cookbook.example;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CookbookTools {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

	/**
	 * The document to extend
	 */
	static protected DSSDocument toExtendDocument;

	/**
	 * The object which is in charge of digesting and encrypting the data to
	 * sign.
	 */
	static protected AbstractSignatureTokenConnection signingToken;

	/**
	 * This object contains the private key associated to the signing
	 * certificate.
	 */
	static protected DSSPrivateKeyEntry privateKey;

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
	 * This method sets the common parameters.
	 * 
	 * @throws IOException
	 */
	protected static void preparePKCS12TokenAndKey() throws IOException {
		signingToken = new Pkcs12SignatureToken("src/main/resources/user_a_rsa.p12", "password");
		privateKey = signingToken.getKeys().get(0);
	}

	protected static MockTSPSource getMockTSPSource() throws Exception {
		return new MockTSPSource(new CertificateService().generateTspCertificate(SignatureAlgorithm.RSA_SHA256));
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

}
