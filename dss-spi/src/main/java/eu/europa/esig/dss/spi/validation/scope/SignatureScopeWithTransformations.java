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
package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The signature scope with the performed transforms
 */
public abstract class SignatureScopeWithTransformations extends SignatureScope {

	private static final long serialVersionUID = -7049827869970167023L;

	/** List of transform definitions */
	private final List<String> transformations;

	/**
	 * Default constructor with a name extracted from a document
	 *
	 * @param document {@link DSSDocument}
	 * @param transformations list of {@link String} transform definitions
	 */
	protected SignatureScopeWithTransformations(final DSSDocument document, final List<String> transformations) {
		this(document.getName(), document, transformations);
	}

	/**
	 * Default constructor with a name provided
	 *
	 * @param name {@link String} filename
	 * @param document {@link DSSDocument}
	 * @param transformations list of {@link String} transform definitions
	 */
	protected SignatureScopeWithTransformations(final String name, final DSSDocument document, final List<String> transformations) {
		super(name, document);
		this.transformations = transformations;
	}

	/**
	 * Adds a description to the signature scope if needed
	 *
	 * @param description {@link String} to add
	 * @return {@link String}
	 */
	protected String addTransformationIfNeeded(String description) {
		if (Utils.isCollectionNotEmpty(transformations)) {
			description += " with transformations.";
		}
		return description;
	}

	@Override
	public List<String> getTransformations() {
		return transformations;
	}

	@Override
	public String toString() {
		return "SignatureScopeWithTransformations{" +
				"transformations=" + transformations +
				"} " + super.toString();
	}

}
