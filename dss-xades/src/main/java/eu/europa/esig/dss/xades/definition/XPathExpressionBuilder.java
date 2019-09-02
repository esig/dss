package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.model.DSSException;

public class XPathExpressionBuilder {

	private final static String FROM_CURRENT_POSITION = "./";
	private final static String ALL = "//";
	private final static String COLON = ":";
	private final static String SLASH = "/";
	private final static String ATTRIBUTE = "@";

	private boolean fromCurrentPosition = false;
	private boolean all = false;
	private DSSElement[] elements;
	private DSSAttribute attribute;

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

	public XPathExpressionBuilder attribute(DSSAttribute attribute) {
		this.attribute = attribute;
		return this;
	}

	public String build() {
		StringBuffer sb = new StringBuffer();

		if (fromCurrentPosition) {
			sb.append(FROM_CURRENT_POSITION);
		} else if (all) {
			sb.append(ALL);
		} else {
			throw new DSSException("Not supported");
		}

		int nbElements = elements.length;
		for (int i = 0; i < nbElements; i++) {
			sb.append(getElement(elements[i]));
			if (i < nbElements - 1) {
				sb.append(SLASH);
			}
		}

		if (attribute != null) {
			sb.append(SLASH).append(getAttribute(attribute));
		}

		return sb.toString();
	}

	private StringBuffer getElement(DSSElement element) {
		StringBuffer sb = new StringBuffer();
		DSSNamespace namespace = element.getNamespace();
		if (namespace != null) {
			sb.append(namespace.getPrefix());
			sb.append(COLON);
		}
		sb.append(element.getTagName());
		return sb;
	}

	private StringBuffer getAttribute(DSSAttribute attribute) {
		StringBuffer sb = new StringBuffer();
		sb.append(ATTRIBUTE);
		sb.append(attribute.getAttributeName());
		return sb;
	}

}
