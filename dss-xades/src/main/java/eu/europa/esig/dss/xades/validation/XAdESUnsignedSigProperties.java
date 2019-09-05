package eu.europa.esig.dss.xades.validation;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public class XAdESUnsignedSigProperties extends XAdESSigProperties {

	XAdESUnsignedSigProperties(Element signaturePropties, XPathQueryHolder xPathQueryHolder) {
		super(signaturePropties, xPathQueryHolder);
	}
	
	public static XAdESUnsignedSigProperties build(Element signatureElement, XPathQueryHolder xPathQueryHolder) {
		Element unsignedSignatureProperties = getUnsignedSignaturePropertiesDom(signatureElement, xPathQueryHolder);
		return new XAdESUnsignedSigProperties(unsignedSignatureProperties, xPathQueryHolder);
	}

	protected static Element getUnsignedSignaturePropertiesDom(Element signatureElement, XPathQueryHolder xPathQueryHolder) {
		return DomUtils.getElement(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
	}

}
