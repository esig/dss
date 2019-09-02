package eu.europa.esig.dss.xades.validation;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.xades.definition.XAdESPaths;

public class XAdESUnsignedSigProperties extends XAdESSigProperties {

	XAdESUnsignedSigProperties(Element signaturePropties, XAdESPaths xadesPaths) {
		super(signaturePropties, xadesPaths);
	}
	
	public static XAdESUnsignedSigProperties build(Element signatureElement, XAdESPaths xadesPaths) {
		Element unsignedSignatureProperties = getUnsignedSignaturePropertiesDom(signatureElement, xadesPaths);
		return new XAdESUnsignedSigProperties(unsignedSignatureProperties, xadesPaths);
	}

	protected static Element getUnsignedSignaturePropertiesDom(Element signatureElement, XAdESPaths xadesPaths) {
		return DomUtils.getElement(signatureElement, xadesPaths.getUnsignedSignaturePropertiesPath());
	}

}
