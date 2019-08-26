package eu.europa.esig.dss.xades.signature;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;

public class PrettyPrintTransformer {
	
	private static final String NEW_LINE = "\n";
	private static final String SPACE = " ";
	
	private Document ownerDocument;
	private int indentAmount = DomUtils.TRANSFORMER_INDENT_NUMBER; // 4 by default
	
	/**
	 * Configures the amount of spaces to add
	 * @param indentAmount {@code int}
	 */
	public void setIndentAmount(int indentAmount) {
		this.indentAmount = indentAmount;
	}
	
	/**
	 * Indents the provided {@code nodeToTransform}, by keeping the original indents if present
	 * @param nodeToTransform {@link Node} to be indented
	 * @return {@link Node} with indents
	 */
	public Node transform(final Node nodeToTransform) {
		Node clonedNode = nodeToTransform.cloneNode(true);
		ownerDocument = clonedNode.getOwnerDocument();
		return indent(clonedNode, 1);
	}
	
	private Node indent(final Node nodeToTransform, final int level) {
		if (hasElementChilds(nodeToTransform)) {
			String indentString = getIndentString(level);
			boolean skip = false;
			Node childNode = nodeToTransform.getFirstChild();
			while (childNode != null) {
				if (Node.TEXT_NODE == childNode.getNodeType()) {
					skip = true;
				} else {
					if (!skip && Utils.isStringNotEmpty(indentString)) {
						Node indentNode = getIndentNode(indentString);
						nodeToTransform.insertBefore(indentNode, childNode);
					}
					skip = false;
					childNode = indent(childNode, level + 1);
				}
				childNode = childNode.getNextSibling();
			}
			if (!skip) {
				indentString = getIndentString(level-1);
				Node indentNode = getIndentNode(indentString);
				nodeToTransform.appendChild(indentNode);
			}
		}
		return nodeToTransform;
	}
	
	private Node getIndentNode(final String indentString) {
		return ownerDocument.createTextNode(indentString);
	}
	
	private String getIndentString(final int level) {
		int spacesExpected = level * indentAmount;
		StringBuilder stringBuilder = new StringBuilder(NEW_LINE);
		for (int ii = 0; ii < spacesExpected; ii++) {
			stringBuilder.append(SPACE);
		}
		return stringBuilder.toString();
	}
	
	private boolean hasElementChilds(Node node) {
		if (node == null) {
			return false;
		}
		NodeList childNodes = node.getChildNodes();
		for (int ii = 0; ii < childNodes.getLength(); ii++) {
			Node item = childNodes.item(ii);
			if (Node.ELEMENT_NODE == item.getNodeType()) {
				return true;
			}
		}
		return false;
	}

}
