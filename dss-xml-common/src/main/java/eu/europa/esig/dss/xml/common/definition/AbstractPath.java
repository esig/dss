/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xml.common.definition;

import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;

import java.io.Serializable;

/**
 * Contains a list of common XML xpaths
 */
public abstract class AbstractPath implements Serializable {

	private static final long serialVersionUID = 4685307161693054765L;

	/**
	 * Default constructor
	 */
	protected AbstractPath() {
		// empty
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element}
	 *
	 * @param element {@link DSSElement}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery all(DSSElement element) {
		return XPathQueryBuilder.all().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element} from the current position
	 *
	 * @param element {@link DSSElement}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery fromCurrentPosition(DSSElement element) {
		return XPathQueryBuilder.fromCurrentPosition().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element} from the current position
	 *
	 * @param element {@link DSSElement}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery allFromCurrentPosition(DSSElement element) {
		return XPathQueryBuilder.allFromCurrentPosition().element(element).build();
	}

	/**
	 * Builds the xpath expression to return entries of the given {@code element}s array
	 *
	 * @param elements an array of {@link DSSElement}s
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery all(DSSElement... elements) {
		return XPathQueryBuilder.all().elements(elements).build();
	}

	/**
	 * Builds the xpath expression to return entries of the {@code element}
	 * which are not child of {@code notChildOf} element
	 *
	 * @param element {@link DSSElement}
	 * @param notChildOf {@link DSSElement}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery allNotParent(DSSElement element, DSSElement notChildOf) {
		return XPathQueryBuilder.all().element(element).notChildOf(notChildOf).build();
	}

	/**
	 * Builds the xpath expression to return entries starting from the current position
	 *
	 * @param elements {@link DSSElement}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery fromCurrentPosition(DSSElement... elements) {
		return XPathQueryBuilder.fromCurrentPosition().elements(elements).build();
	}

	/**
	 * Builds the xpath expression to return entries starting from the current position
	 * with the given {@code attribute}
	 *
	 * @param element {@link DSSElement}
	 * @param attribute {@link DSSAttribute}
	 * @return {@link XPathQuery} xpath expression
	 */
	public static XPathQuery fromCurrentPosition(DSSElement element, DSSAttribute attribute) {
		return XPathQueryBuilder.fromCurrentPosition().element(element).attribute(attribute).build();
	}

}
