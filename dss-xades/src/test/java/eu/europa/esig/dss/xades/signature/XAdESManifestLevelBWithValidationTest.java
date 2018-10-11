package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESManifestLevelBWithValidationTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {

		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, documents);

		documentToSign = builder.build();

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		signatureParameters.setManifestSignature(true);

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));

		FileDocument fileDoc = new FileDocument("src/test/resources/sample.txt");

		DigestDocument digestDocument = new DigestDocument();
		digestDocument.setName(fileDoc.getName());
		digestDocument.addDigest(DigestAlgorithm.SHA512, fileDoc.getDigest(DigestAlgorithm.SHA512));

		documents.add(digestDocument);

		validator.setDetachedContents(documents);
		return validator;
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		boolean foundManifestEntry = false;
		boolean foundManifest = false;
		boolean foundSignedProperties = false;
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			switch (xmlDigestMatcher.getType()) {
			case MANIFEST:
				foundManifest = true;
				break;
			case MANIFEST_ENTRY:
				foundManifestEntry = true;
				break;
			case SIGNED_PROPERTIES:
				foundSignedProperties = true;
				break;
			default:
				break;
			}
		}

		assertTrue(foundManifest);
		assertTrue(foundManifestEntry);
		assertTrue(foundSignedProperties);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
