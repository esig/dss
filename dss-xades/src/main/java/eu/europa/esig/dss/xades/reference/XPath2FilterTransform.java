package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XPath2FilterTransform extends XPathTransform {
	
	public static final String FILTER_ATTRIBUTE = "Filter";
	
	private final String filter;

	public XPath2FilterTransform(String xPathExpression, String filter) {
		super(Transforms.TRANSFORM_XPATH2FILTER, xPathExpression);
		this.filter = filter;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		transform.setAttribute(FILTER_ATTRIBUTE, filter);
		return transform;
	}

}
