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
package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.model.Digest;

import java.util.List;

/**
 * Defines a full XML document signature scope
 */
public final class XmlFullSignatureScope extends XmlRootSignatureScope {

	/**
	 * Constructor with document name
	 *
	 * @param name {@link String} document name
	 * @param transformations a list of {@link String} transform descriptions
	 * @param digest {@link Digest} of the element
	 */
	protected XmlFullSignatureScope(String name, List<String> transformations, Digest digest) {
		super(name, transformations, digest);
	}

}
