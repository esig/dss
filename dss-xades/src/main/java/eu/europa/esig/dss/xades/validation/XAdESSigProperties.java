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

import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.xades.definition.XAdESPath;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * XAdES signed properties
 */
public abstract class XAdESSigProperties implements SignatureProperties<XAdESAttribute> {

	private static final long serialVersionUID = -8950099614582666431L;

	/** Signature properties element */
	private final Element signaturePropertiesDom;

	/** The XAdES XPaths */
	private final XAdESPath xadesPaths;

	/**
	 * Default constructor
	 *
	 * @param signatureProperties {@link Element}
	 * @param xadesPaths {@link XAdESPath}
	 */
	XAdESSigProperties(Element signatureProperties, XAdESPath xadesPaths) {
		this.signaturePropertiesDom = signatureProperties;
		this.xadesPaths = xadesPaths;
	}
	
	@Override
	public boolean isExist() {
		return signaturePropertiesDom != null;
	}

	@Override
	public List<XAdESAttribute> getAttributes() {
		List<XAdESAttribute> unsignedAttributes = new ArrayList<>();
		if (signaturePropertiesDom != null && signaturePropertiesDom.hasChildNodes()) {
			final NodeList unsignedProperties = signaturePropertiesDom.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {
				Node node = unsignedProperties.item(ii);
				if (isElementNode(node)) {
					XAdESAttribute unsignedAttribute = new XAdESAttribute((Element) node, xadesPaths);
					unsignedAttributes.add(unsignedAttribute);
				}
			}
		}
		return unsignedAttributes;
	}
	
	/**
	 * Checks is the element is a proper "UnsignedSignatureProperties" element
	 * @return TRUE if the element is a compatible Unsigned Attribute, FALSE otherwise
	 */
	private boolean isElementNode(Node node) {
		return node.getNodeType() == Node.ELEMENT_NODE;
	}

}
