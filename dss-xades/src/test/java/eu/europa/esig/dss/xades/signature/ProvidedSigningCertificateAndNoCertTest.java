package eu.europa.esig.dss.xades.signature;

import java.io.File;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xmldsig.XMLDSigPaths;

public class ProvidedSigningCertificateAndNoCertTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.txt"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument signedDoc = super.sign();
		return removeKeyInfo(signedDoc);
	}

	private DSSDocument removeKeyInfo(DSSDocument signedDoc) {
		Document dom = DomUtils.buildDOM(signedDoc);
		try {
			Element root = dom.getDocumentElement();
			XPathExpression xpath = DomUtils.createXPathExpression(XMLDSigPaths.KEY_INFO_PATH);
			Element keyInfoTag = (Element) xpath.evaluate(root, XPathConstants.NODE);
			keyInfoTag.getParentNode().removeChild(keyInfoTag);
		} catch (Exception e) {
			throw new DSSException("Unable to remove the KeyInfo element", e);
		}

		byte[] bytes = DSSXMLUtils.serializeNode(dom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		inMemoryDocument.setName("bla.xml");
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.defineSigningCertificate(getSigningCert());
		return validator;
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {

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
