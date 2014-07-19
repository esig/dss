/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.scope;

import java.util.List;

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
