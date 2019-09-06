package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.SantuarioInitializer;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;

public class XAdESLevelBEnvelopedWithXPath2FilterTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		SantuarioInitializer.init();

		documentToSign = new FileDocument(new File("src/test/resources/sampleWithPlaceOfSignature.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setXPathLocationString("//placeOfSignature");

		List<DSSReference> dssReferences = new ArrayList<DSSReference>();
		DSSReference reference = new DSSReference();
		reference.setContents(documentToSign);
		reference.setId("REF-ID1");
		reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference.setUri("");
		List<DSSTransform> transforms1 = new ArrayList<DSSTransform>();
		XPath2FilterEnvelopedSignatureTransform transform1 = new XPath2FilterEnvelopedSignatureTransform();
		transforms1.add(transform1);
		reference.setTransforms(transforms1);
		dssReferences.add(reference);

		signatureParameters.setReferences(dssReferences);

		service = new XAdESService(getCompleteCertificateVerifier());
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
