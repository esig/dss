package eu.europa.esig.dss.xades.reference;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public interface DSSTransform {
	
	/**
	 * Performs transformation on the given {@code node} and returns resulting bytes
	 * @param node {@link Node} to perform transformation on
	 * @return byte array
	 */
	byte[] getBytesAfterTranformation(Node node);
	
	/**
	 * Creates a Transform element DOM and appends it to the {@code parentNode}
	 * @param document {@link Document} to add transform for
	 * @param parentNode {@link Element} to append transform to
	 * @return created transform {@link Element}
	 */
	Element createTransform(Document document, Element parentNode);

}
