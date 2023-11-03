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
package eu.europa.esig.xades.definition.xades132;


import eu.europa.esig.dss.xml.common.definition.DSSAttribute;

/**
 * The XAdES 1.3.2 attributes
 */
public enum XAdES132Attribute implements DSSAttribute {

	/** Encoding */
	ENCODING("Encoding"),

	/** Id */
	ID("Id"),

	/** ObjectReference */
	OBJECT_REFERENCE("ObjectReference"),

	/** Qualifier */
	QUALIFIER("Qualifier"),

	/** referencedData */
	REFERENCED_DATA("referencedData"),

	/** Target */
	TARGET("Target"),

	/** URI */
	URI("URI");

	/** Attribute name */
	private final String attributeName;

	/**
	 * Default constructor
	 *
	 * @param attributeName {@link String}
	 */
	XAdES132Attribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
