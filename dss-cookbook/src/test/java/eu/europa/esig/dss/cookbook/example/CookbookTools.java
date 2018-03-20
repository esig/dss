package eu.europa.esig.dss.cookbook.example;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public class CookbookTools extends PKIFactoryAccess {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

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

	protected void testFinalDocument(DSSDocument signedDocument) {
		assertNotNull(signedDocument);
		assertNotNull(DSSUtils.toByteArray(signedDocument));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signatureWrapper : signatures) {
			assertTrue(signatureWrapper.isBLevelTechnicallyValid());

			List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
			for (TimestampWrapper timestampWrapper : timestampList) {
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				assertTrue(timestampWrapper.isSignatureValid());
			}
		}
	}

	/**
	 * This method retrieves an instance of PKCS12 keystore
	 * 
	 */
	protected SignatureTokenConnection getPkcs12Token() throws IOException {
		return getToken();
	}

	protected TSPSource getOnlineTSPSource() {
		return getGoodTsa();
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
