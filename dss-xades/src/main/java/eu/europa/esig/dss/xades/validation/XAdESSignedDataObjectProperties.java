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
package eu.europa.esig.dss.xades.validation;

import org.w3c.dom.Element;

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.xades.definition.XAdESPaths;

/**
 * Builds {@code XAdESSignedDataObjectProperties}
 */
public class XAdESSignedDataObjectProperties extends XAdESSigProperties {

	private static final long serialVersionUID = -8340742069424121438L;

	/**
	 * Default constructor
	 *
	 * @param signatureProperties {@link Element}
	 * @param xadesPaths {@link XAdESPaths}
	 */
	XAdESSignedDataObjectProperties(Element signatureProperties, XAdESPaths xadesPaths) {
		super(signatureProperties, xadesPaths);
	}

	/**
	 * Builds {@code XAdESSignedDataObjectProperties}
	 *
	 * @param signatureElement {@link Element} signature element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link XAdESSignedDataObjectProperties}
	 */
	public static XAdESSignedDataObjectProperties build(Element signatureElement, XAdESPaths xadesPaths) {
		Element signedSignatureProperties = getSignedSignaturePropertiesDom(signatureElement, xadesPaths);
		return new XAdESSignedDataObjectProperties(signedSignatureProperties, xadesPaths);
	}

	/**
	 * Gets xades:SignedDataObjectProperties element
	 *
	 * @param signatureElement {@link Element} signature element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link Element}
	 */
	protected static Element getSignedSignaturePropertiesDom(Element signatureElement, XAdESPaths xadesPaths) {
		return DomUtils.getElement(signatureElement, xadesPaths.getSignedDataObjectPropertiesPath());
	}

}