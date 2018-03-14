package eu.europa.esig.dss.xades.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESMultipleManifestLevelBTest extends AbstractPkiFactoryTestMultipleDocumentsSignatureService<XAdESSignatureParameters> {

	private MultipleDocumentsSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	@Before
	public void init() throws Exception {

		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder1 = new ManifestBuilder("manifest-sha512", DigestAlgorithm.SHA512, documents);
		ManifestBuilder builder2 = new ManifestBuilder("manifest-sha256", DigestAlgorithm.SHA256, documents);

		documentToSigns = Arrays.asList(builder1.build(), builder2.build());

		signatureParameters = new XAdESSignatureParameters();
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
	protected MultipleDocumentsSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

}
