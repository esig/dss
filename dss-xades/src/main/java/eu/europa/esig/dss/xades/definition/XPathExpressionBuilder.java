package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.model.DSSException;

public class XPathExpressionBuilder {

	private static final String ALL_PATH = "//";
	private static final String FROM_CURRENT_POSITION_PATH = "./";
	private static final String ALL_FROM_CURRENT_POSITION_PATH = ".//";
	private static final String COLON_PATH = ":";
	private static final String SLASH_PATH = "/";
	private static final String ATTRIBUTE_PATH = "@";

	private boolean fromCurrentPosition = false;
	private boolean all = false;
	private DSSElement[] elements;
	private DSSAttribute attribute;
	private DSSElement notParentOf;

	public XPathExpressionBuilder fromCurrentPosition() {
		return fromCurrentPosition(true);
	}

	public XPathExpressionBuilder fromCurrentPosition(boolean fromCurrentPosition) {
		this.fromCurrentPosition = fromCurrentPosition;
		return this;
	}

	public XPathExpressionBuilder all() {
		return all(true);
	}

	public XPathExpressionBuilder all(boolean all) {
		this.all = all;
		return this;
	}

	public XPathExpressionBuilder element(DSSElement element) {
		this.elements = new DSSElement[] { element };
		return this;
	}

	public XPathExpressionBuilder elements(DSSElement[] elements) {
		this.elements = elements;
		return this;
	}

	public XPathExpressionBuilder notParentOf(DSSElement notParentOf) {
		this.notParentOf = notParentOf;
		return this;
	}

	public XPathExpressionBuilder attribute(DSSAttribute attribute) {
		this.attribute = attribute;
		return this;
	}

	public String build() {
		StringBuilder sb = new StringBuilder();

		if (all && fromCurrentPosition) {
			sb.append(ALL_FROM_CURRENT_POSITION_PATH);
		} else if (fromCurrentPosition) {
			sb.append(FROM_CURRENT_POSITION_PATH);
		} else if (all) {
			sb.append(ALL_PATH);
		} else {
			throw new DSSException("Unsupported operation");
		}

		int nbElements = elements.length;
		for (int i = 0; i < nbElements; i++) {
			sb.append(getElement(elements[i]));
			if (i < nbElements - 1) {
				sb.append(SLASH_PATH);
			}
		}

		if (notParentOf != null) {
			sb.append(getNotParent(notParentOf));
		}

		if (attribute != null) {
			sb.append(SLASH_PATH).append(getAttribute(attribute));
		}

		return sb.toString();
	}

	private StringBuilder getElement(DSSElement element) {
		StringBuilder sb = new StringBuilder();
		DSSNamespace namespace = element.getNamespace();
		if (namespace != null) {
			sb.append(namespace.getPrefix());
			sb.append(COLON_PATH);
		}
		sb.append(element.getTagName());
		return sb;
	}

	// "//ds:Signature[not(parent::xades:CounterSignature)]"
	private StringBuilder getNotParent(DSSElement currentNotParentOf) {
		StringBuilder sb = new StringBuilder();
		sb.append("[not(parent::");
		sb.append(getElement(currentNotParentOf));
		sb.append(")]");
		return sb;
	}

	private StringBuilder getAttribute(DSSAttribute currentAttribute) {
		StringBuilder sb = new StringBuilder();
		sb.append(ATTRIBUTE_PATH);
		sb.append(currentAttribute.getAttributeName());
		return sb;
	}

}
