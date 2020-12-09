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
package eu.europa.esig.dss.definition;

/**
 * Contains a list of common XML xpaths
 */
public abstract class AbstractPaths {

	/**
	 * Builds the xpath expression to return entries of the {@code element}
	 *
	 * @param element {@link DSSElement}
	 * @return {@link String} xpath expression
	 */
	public static final String all(DSSElement element) {
		return new XPathExpressionBuilder().all().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element} from the current position
	 *
	 * @param element {@link DSSElement}
	 * @return {@link String} xpath expression
	 */
	public static final String fromCurrentPosition(DSSElement element) {
		return new XPathExpressionBuilder().fromCurrentPosition().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element} from the current position
	 *
	 * @param element {@link DSSElement}
	 * @return {@link String} xpath expression
	 */
	public static final String allFromCurrentPosition(DSSElement element) {
		return new XPathExpressionBuilder().all().fromCurrentPosition().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the given {@code element}s array
	 *
	 * @param elements an array of {@link DSSElement}s
	 * @return {@link String} xpath expression
	 */
	protected static final String all(DSSElement... elements) {
		return new XPathExpressionBuilder().all().elements(elements).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element}
	 * which are not parent of {@code notParentOf}
	 *
	 * @param element {@link DSSElement}
	 * @param notParentOf {@link DSSElement}
	 * @return {@link String} xpath expression
	 */
	protected static String allNotParent(DSSElement element, DSSElement notParentOf) {
		return new XPathExpressionBuilder().all().element(element).notParentOf(notParentOf).build();
	}

	/**
	 * Builds the xpath expression to return entries starting from the current position
	 *
	 * @param elements {@link DSSElement}
	 * @return {@link String} xpath expression
	 */
	protected static final String fromCurrentPosition(DSSElement... elements) {
		return new XPathExpressionBuilder().fromCurrentPosition().elements(elements).build();
	}

	/**
	 * Builds the xpath expression to return entries starting from the current position
	 * with the given {@code attribute}
	 *
	 * @param element {@link DSSElement}
	 * @param attribute {@link DSSAttribute}
	 * @return {@link String} xpath expression
	 */
	protected static final String fromCurrentPosition(DSSElement element, DSSAttribute attribute) {
		return new XPathExpressionBuilder().fromCurrentPosition().element(element).attribute(attribute).build();
	}

}
