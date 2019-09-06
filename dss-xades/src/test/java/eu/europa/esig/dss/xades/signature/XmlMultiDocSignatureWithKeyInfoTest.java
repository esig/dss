package eu.europa.esig.dss.xades.signature;

import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XmlMultiDocSignatureWithKeyInfoTest extends AbstractPkiFactoryTestMultipleDocumentsSignatureService<XAdESSignatureParameters> {

	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	@BeforeEach
	public void init() throws Exception {
		documentToSigns = Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/sample.xml"),
				new FileDocument("src/test/resources/sampleWithPlaceOfSignature.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignKeyInfo(true);
		signatureParameters.setKeyInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
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
