package eu.europa.esig.dss.xades.reference;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XsltTransform extends ComplexTransform {
	
	private final Document content;

	public XsltTransform(Document content) {
		super(Transforms.TRANSFORM_XSLT);
		this.content = content;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		final Element contextDocumentElement = content.getDocumentElement();
		document.adoptNode(contextDocumentElement);
		return (Element) transform.appendChild(contextDocumentElement);
	}

}
