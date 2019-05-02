package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;

public class XPath2FilterTransform extends XPathTransform {
	
	private static final String FILTER_ATTRIBUTE = "Filter";
	private static final String XPATH2_FILTER_NAMESPACE = "http://www.w3.org/2002/06/xmldsig-filter2";
	
	private final String filter;

	public XPath2FilterTransform(String xPathExpression, String filter) {
		super(Transforms.TRANSFORM_XPATH2FILTER, xPathExpression);
		this.filter = filter;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = DomUtils.addElement(document, parentNode, namespace, DS_TRANSFORM);
		transform.setAttribute(ALGORITHM, algorithm);
		// XPath element must have a specific namespace
		Element xPathElement = DomUtils.addTextElement(document, transform, XPATH2_FILTER_NAMESPACE, DS_XPATH, xPathExpression);
		xPathElement.setPrefix("dsig-xpath");
		xPathElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:dsig-xpath", XPATH2_FILTER_NAMESPACE);
		xPathElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", namespace);
		xPathElement.setAttribute(FILTER_ATTRIBUTE, filter);
		return xPathElement;
	}

}
