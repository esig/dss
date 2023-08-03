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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.xades.definition.XAdESPaths;

/**
 * Unsigned XAdES signature properties
 */
public class XAdESUnsignedSigProperties extends XAdESSigProperties {

	private static final long serialVersionUID = -1323693650418213811L;

	/**
	 * Default constructor
	 *
	 * @param unsignedSignatureProperties {@link Element} unsigned signature properties
	 * @param xadesPaths {@link XAdESPaths}
	 */
	public XAdESUnsignedSigProperties(Element unsignedSignatureProperties, XAdESPaths xadesPaths) {
		super(unsignedSignatureProperties, xadesPaths);
	}

	/**
	 * Builds {code XAdESUnsignedSigProperties}
	 *
	 * @param signatureElement {@link Element} signature element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link XAdESUnsignedSigProperties}
	 */
	public static XAdESUnsignedSigProperties build(Element signatureElement, XAdESPaths xadesPaths) {
		Element unsignedSignatureProperties = getUnsignedSignaturePropertiesDom(signatureElement, xadesPaths);
		return new XAdESUnsignedSigProperties(unsignedSignatureProperties, xadesPaths);
	}

	/**
	 * Gets xades:UnsignedSignatureProperties element
	 *
	 * @param signatureElement {@link Element} signature element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link Element}
	 */
	protected static Element getUnsignedSignaturePropertiesDom(Element signatureElement, XAdESPaths xadesPaths) {
		return DomUtils.getElement(signatureElement, xadesPaths.getUnsignedSignaturePropertiesPath());
	}

}
