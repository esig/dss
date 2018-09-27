package eu.europa.esig.dss.xades.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESManifestFromDigestDocumentsLevelBTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {

		List<DSSDocument> documents = Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/sample.png"),
				new FileDocument("src/test/resources/sample.txt"), new FileDocument("src/test/resources/sample.xml"));

		List<DSSDocument> digestDocuments = new ArrayList<DSSDocument>();
		for (DSSDocument dssDocument : documents) {
			DigestDocument digestDocument = new DigestDocument();
			digestDocument.setName(dssDocument.getName());
			digestDocument.addDigest(DigestAlgorithm.SHA512, dssDocument.getDigest(DigestAlgorithm.SHA512));
			digestDocuments.add(digestDocument);
		}

		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, digestDocuments);

		documentToSign = builder.build();

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setManifestSignature(true);

		service = new XAdESService(getCompleteCertificateVerifier());
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
