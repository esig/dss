package eu.europa.esig.dss.xades.reference;

import java.io.IOException;
import java.util.Map.Entry;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.xades.signature.XAdESSignatureBuilder;

public abstract class ComplexTransform extends AbstractTransform {
	
	private Transform transformObject; // internal object, used to build the Transformation

	public ComplexTransform(String algorithm) {
		super(algorithm);
	}
	
	private void buildTransformObject() {
		try {
			final Document document = DomUtils.buildDOM();
			final Element transformsDom = document.createElementNS(namespace, XAdESSignatureBuilder.DS_TRANSFORMS);
			document.appendChild(transformsDom);
			createTransform(document, transformsDom);
			final NodeList childNodes = transformsDom.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, algorithm, childNodes);
			for (Entry<String, String> namespace : DomUtils.getCurrentNamespaces().entrySet()) {
				transformObject.setXPathNamespaceContext(namespace.getKey(), namespace.getValue());
			}
			this.transformObject = transformObject;
		} catch (XMLSecurityException e) {
			throw new DSSException(String.format("Cannot initialize a transform [%s]", algorithm), e);
		}
	}
	
	@Override
	public byte[] getBytesAfterTranformation(Node node) {
		if (transformObject == null) {
			buildTransformObject();
		}
		try {
			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(node);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (IOException | XMLSecurityException e) {
			throw new DSSException(String.format("Cannot process transformation [%s] on the given DOM object", algorithm), e);
		}
	}

}
