package eu.europa.esig.dss.xades.validation;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.validation.timestamp.SignatureProperties;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public abstract class XAdESSigProperties implements SignatureProperties<XAdESAttribute> {
	
	final Element signatureProptiesDom;
	final XPathQueryHolder xPathQueryHolder;
	
	XAdESSigProperties(Element signaturePropties, XPathQueryHolder xPathQueryHolder) {
		this.signatureProptiesDom = signaturePropties;
		this.xPathQueryHolder = xPathQueryHolder;
	}
	
	@Override
	public boolean isExist() {
		return signatureProptiesDom != null;
	}

	@Override
	public List<XAdESAttribute> getAttributes() {
		List<XAdESAttribute> unsignedAttributes = new ArrayList<XAdESAttribute>();
		if (signatureProptiesDom != null && signatureProptiesDom.hasChildNodes()) {
			final NodeList unsignedProperties = signatureProptiesDom.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {
				Node node = unsignedProperties.item(ii);
				if (isElementNode(node)) {
					XAdESAttribute unsignedAttribute = new XAdESAttribute((Element) node, xPathQueryHolder);
					unsignedAttributes.add(unsignedAttribute);
				}
			}
		}
		return unsignedAttributes;
	}
	
	/**
	 * Checks is the element is a proper "UnsignedSignatureProperties" element
	 * @return TRUE if the element is a compatible Unsigned Attribute, FALSE otherwise
	 */
	private boolean isElementNode(Node node) {
		return node.getNodeType() == Node.ELEMENT_NODE;
	}

}
