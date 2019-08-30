package eu.europa.esig.dss.xades.validation;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.xades.XAdESPaths;

public class XAdESSignedDataObjectProperties extends XAdESSigProperties {

	XAdESSignedDataObjectProperties(Element signaturePropties, XAdESPaths xadesPaths) {
		super(signaturePropties, xadesPaths);
	}
	
	public static XAdESSignedDataObjectProperties build(Element signatureElement, XAdESPaths xadesPaths) {
		Element signedSignatureProperties = getSignedSignaturePropertiesDom(signatureElement, xadesPaths);
		return new XAdESSignedDataObjectProperties(signedSignatureProperties, xadesPaths);
	}

	protected static Element getSignedSignaturePropertiesDom(Element signatureElement, XAdESPaths xadesPaths) {
		return DomUtils.getElement(signatureElement, xadesPaths.getSignedDataObjectPropertiesPath());
	}

}