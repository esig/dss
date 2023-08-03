/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jaxb.common.definition;

/**
 * Builds an XPath expression
 */
public class XPathExpressionBuilder {

	/** The path to search all entries in the whole document */
	private static final String ALL_PATH = "//";

	/** The path to search starting from the current element */
	private static final String FROM_CURRENT_POSITION_PATH = "./";

	/** The path to search all entries starting from the current element */
	private static final String ALL_FROM_CURRENT_POSITION_PATH = ".//";

	/** The namespace separator */
	private static final String COLON_PATH = ":";

	/** Defines the next element */
	private static final String SLASH_PATH = "/";

	/** Defines an attribute value */
	private static final String ATTRIBUTE_PATH = "@";

	/**
	 * Defines if to start search from the current position
	 *
	 * Default: false
	 */
	private boolean fromCurrentPosition = false;

	/**
	 * Defines if to search all occurrences
	 *
	 * Default: false
	 */
	private boolean all = false;

	/**
	 * The elements path
	 */
	private DSSElement[] elements;

	/**
	 * The attribute to search
	 */
	private DSSAttribute attribute;

	/**
	 * Defines that the looking element should not be a parent of this element
	 */
	private DSSElement notParentOf;

	/**
	 * Default constructor instantiating object with empty configuration
	 */
	public XPathExpressionBuilder() {
		// empty
	}

	/**
	 * Starts XPath from the current position
	 *
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder fromCurrentPosition() {
		return fromCurrentPosition(true);
	}

	/**
	 * Defines if to start XPath from the current position
	 *
	 * @param fromCurrentPosition if to start XPath from the current position
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder fromCurrentPosition(boolean fromCurrentPosition) {
		this.fromCurrentPosition = fromCurrentPosition;
		return this;
	}

	/**
	 * Defines if to search all element occurrences
	 *
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder all() {
		return all(true);
	}

	/**
	 * Defines if to search all element occurrences
	 *
	 * @param all if to search all element occurrences
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder all(boolean all) {
		this.all = all;
		return this;
	}

	/**
	 * Defines the element to search
	 *
	 * @param element {@link DSSElement} to search
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder element(DSSElement element) {
		this.elements = new DSSElement[] { element };
		return this;
	}

	/**
	 * Defines the element path to search
	 *
	 * @param elements a {@link DSSElement}s chain to search
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder elements(DSSElement[] elements) {
		this.elements = elements;
		return this;
	}

	/**
	 * Defines that the looking element shall not be a parent of {@code notParentOf} element
	 *
	 * @param notParentOf {@link DSSElement} child element that shall not be present
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder notParentOf(DSSElement notParentOf) {
		this.notParentOf = notParentOf;
		return this;
	}

	/**
	 * Defines the attribute to search
	 *
	 * @param attribute {@link DSSAttribute}
	 * @return this {@link XPathExpressionBuilder}
	 */
	public XPathExpressionBuilder attribute(DSSAttribute attribute) {
		this.attribute = attribute;
		return this;
	}

	/**
	 * Builds the XPath expression
	 *
	 * @return {@link String} XPath expression
	 */
	public String build() {
		StringBuilder sb = new StringBuilder();

		if (all && fromCurrentPosition) {
			sb.append(ALL_FROM_CURRENT_POSITION_PATH);
		} else if (fromCurrentPosition) {
			sb.append(FROM_CURRENT_POSITION_PATH);
		} else if (all) {
			sb.append(ALL_PATH);
		} else {
			throw new UnsupportedOperationException("Unsupported operation");
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
