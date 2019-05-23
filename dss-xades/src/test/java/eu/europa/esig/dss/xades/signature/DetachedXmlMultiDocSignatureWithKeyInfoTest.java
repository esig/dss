package eu.europa.esig.dss.xades.signature;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class DetachedXmlMultiDocSignatureWithKeyInfoTest extends AbstractPkiFactoryTestMultipleDocumentsSignatureService<XAdESSignatureParameters> {

	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	@Before
	public void init() throws Exception {
		documentToSigns = Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/sample.xml"),
				new FileDocument("src/test/resources/sampleWithPlaceOfSignature.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignKeyInfo(true);
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setDetachedContents(documentToSigns);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
		return validator;
	}

	@Override
	protected MultipleDocumentsSignatureService<XAdESSignatureParameters> getService() {
		return new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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
