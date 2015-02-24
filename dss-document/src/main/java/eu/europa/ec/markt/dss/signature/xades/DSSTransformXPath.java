package eu.europa.ec.markt.dss.signature.xades;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.signature.DSSDocument;

/**
 * This class implement the logic of {@code Transforms.TRANSFORM_XPATH}.
 *
 * // TODO (06/12/2014): Can be easily adapted to support more transformations
 *
 */
class DSSTransformXPath {

	private Document document;
	private DSSTransform dssTransform;

	public DSSTransformXPath(final DSSTransform dssTransform) {

		this.dssTransform = dssTransform;
		document = DSSXMLUtils.buildDOM();
		final Element transformDom = document.createElementNS(XMLSignature.XMLNS, SignatureBuilder.DS_TRANSFORM);
		document.appendChild(transformDom);

		SignatureBuilder.createTransform(document, dssTransform, transformDom);
	}

	public byte[] transform(final DSSDocument input) throws DSSException {
		try {
			final String dssTransformAlgorithm = dssTransform.getAlgorithm();
			final NodeList childNodes = document.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, dssTransformAlgorithm, childNodes);

			final byte[] bytes = input.getBytes();
			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(bytes);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public byte[] transform(final Node input) throws DSSException {
		try {
			final String dssTransformAlgorithm = dssTransform.getAlgorithm();
			final NodeList childNodes = document.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, dssTransformAlgorithm, childNodes);

			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(input);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}
}
