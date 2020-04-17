package eu.europa.esig.dss.xades.validation.xsw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class XAdESEnvelopedXSWTest extends AbstractXAdESTestValidation {
	
	private static DSSDocument document = new FileDocument(new File("src/test/resources/validation/xsw/original.xml"));

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
		
		XmlSignatureDigestReference signatureDigestReference = signatureById.getSignatureDigestReference();
		assertNotNull(signatureDigestReference);

		Document documentDom = DomUtils.buildDOM(document);
		NodeList nodeList = DomUtils.getNodeList(documentDom.getDocumentElement(), XMLDSigPaths.SIGNATURE_PATH);
		Element signatureElement = (Element) nodeList.item(0);
		byte[] canonicalizedSignatureElement = DSSXMLUtils.canonicalizeSubtree(signatureDigestReference.getCanonicalizationMethod(), signatureElement);
		byte[] digest = DSSUtils.digest(signatureDigestReference.getDigestMethod(), canonicalizedSignatureElement);
		
		String signatureReferenceDigestValue = Utils.toBase64(signatureDigestReference.getDigestValue());
		String signatureElementDigestValue = Utils.toBase64(digest);
		assertEquals(signatureReferenceDigestValue, signatureElementDigestValue);
	}

}
