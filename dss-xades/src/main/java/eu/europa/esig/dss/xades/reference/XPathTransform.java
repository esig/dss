package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;

public class XPathTransform extends ComplexTransform {
	
	protected static final String DS_XPATH = "ds:XPath";
	
	protected final String xPathExpression;
	
	protected XPathTransform(String algorithm, String xPathExpression) {
		super(algorithm);
		this.xPathExpression = xPathExpression;
	}

	public XPathTransform(String xPathExpression) {
		this(Transforms.TRANSFORM_XPATH, xPathExpression);
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		return DomUtils.addTextElement(document, transform, namespace, DS_XPATH, xPathExpression);
	}

}
