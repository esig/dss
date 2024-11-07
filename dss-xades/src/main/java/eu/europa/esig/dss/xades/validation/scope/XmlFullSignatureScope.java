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
package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Defines a full XML document signature scope
 */
public final class XmlFullSignatureScope extends XmlRootSignatureScope {

	private static final long serialVersionUID = 1723939599853179050L;

	/**
	 * Constructor with document name
	 *
	 * @param name {@link String} document name
	 * @param document {@link DSSDocument}
	 * @param transformations a list of {@link String} transform descriptions
	 */
	protected XmlFullSignatureScope(final String name, final DSSDocument document, final List<String> transformations) {
		super(name, document, transformations);
	}

}
