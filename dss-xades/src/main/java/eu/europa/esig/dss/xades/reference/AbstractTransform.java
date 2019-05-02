package eu.europa.esig.dss.xades.reference;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;

public abstract class AbstractTransform implements DSSTransform {

	public static final String ALGORITHM = "Algorithm";
	public static final String DS_TRANSFORM = "ds:Transform";
	
	protected final String algorithm;
	protected String namespace = XMLSignature.XMLNS;
	
	public AbstractTransform(String algorithm) {
		this.algorithm = algorithm;
	}
	
	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}
	
	@Override
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transformDom = DomUtils.addElement(document, parentNode, namespace, DS_TRANSFORM);
		transformDom.setAttribute(ALGORITHM, algorithm);
		return transformDom;
	}
	
}
