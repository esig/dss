package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.xml.security.signature.Reference;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;

public class XAdESLevelBBase64TransformTest extends PKIFactoryAccess {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/sample.xml");
	
	@Test
	public void test() {
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test(expected = DSSException.class)
	public void embedXmlWithBase64Test() {

		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEmbedXML(true);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test(expected = DSSException.class)
	public void envelopedBase64TransformTest() {
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test(expected = DSSException.class)
	public void base64WithOtherReferencesTest() {
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		CanonicalizationTransform canonicalizationTransform = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
		transforms.add(canonicalizationTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test(expected = DSSException.class)
	public void doubleBase64TransformTest() {
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		Base64Transform dssTransform2 = new Base64Transform();
		transforms.add(dssTransform2);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test(expected = DSSException.class)
	public void manifestWithBase64Test() {

		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, documents);

		DSSDocument documentToSign = builder.build();
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);
		signatureParameters.setManifestSignature(true);
		
		signAndValidate(documentToSign, signatureParameters);
		
	}
	
	private List<DSSReference> buildReferences(DSSDocument document, List<DSSTransform> transforms) {

		DSSReference ref1 = new DSSReference();
		ref1.setContents(document);
		ref1.setId("r-" + document.getName());
		ref1.setTransforms(transforms);
		ref1.setType(Reference.OBJECT_URI);
		ref1.setUri('#' + document.getName());
		ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		
		List<DSSReference> refs = new ArrayList<DSSReference>();
		refs.add(ref1);
		
		return refs;
		
	}
	
	private void signAndValidate(DSSDocument document, XAdESSignatureParameters signatureParameters) {

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned toSign1 = service.getDataToSign(document, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(document, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
