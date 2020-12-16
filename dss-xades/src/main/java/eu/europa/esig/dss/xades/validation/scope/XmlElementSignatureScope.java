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

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.scope.SignatureScopeWithTransformations;

import java.util.List;

/**
 * XML element signature scope
 */
public class XmlElementSignatureScope extends SignatureScopeWithTransformations {

	/**
	 * Default constructor
	 *
	 * @param xmlId {@link String} id of the element
	 * @param transformations a list of {@link String} transform descriptions
	 * @param digest {@link Digest} of the element
	 */
	protected XmlElementSignatureScope(final String xmlId, final List<String> transformations, final Digest digest) {
		super(xmlId, digest, transformations);
	}

	@Override
	public String getDescription() {
		String description = "The XML element with ID '" + getName() + "'";
		if (isTransformationsNotEmpty()) {
			description = addTransformationDescription(description);
		}
		return description;
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.PARTIAL;
	}

}
