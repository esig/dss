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

import java.util.List;

import eu.europa.esig.dss.validation.SignatureScope;

/**
 *
 */
public class XmlElementSignatureScope extends SignatureScope {

	private final List<String> transformations;

	protected XmlElementSignatureScope(String xmlId, final List<String> transformations) {
		super(xmlId);
		this.transformations = transformations;
	}

	@Override
	public String getDescription() {

		String description = "The XML element with ID '" + getName() + "'";
		if (transformations.isEmpty()) {
			return description;
		} else {
			return addTransformationDescription(description);
		}
	}

	protected String addTransformationDescription(final String description) {

		StringBuilder result = new StringBuilder();
		result.append(description).append(" with transformations: ");
		for (final String transformation : transformations) {
			result.append(transformation).append("; ");
		}
		result.delete(result.length() - 2, result.length()).append(".");
		return result.toString();
	}

	protected List<String> getTransformations() {
		return transformations;
	}
}
