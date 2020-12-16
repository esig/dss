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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The signature scope with the performed transforms
 */
public abstract class SignatureScopeWithTransformations extends SignatureScope {

	/** List of transform definitions */
	private final List<String> transformations;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} document name
	 * @param digest {@link Digest} digest document
	 * @param transformations list of {@link String} transform definitions
	 */
	protected SignatureScopeWithTransformations(final String name, final Digest digest, final List<String> transformations) {
		super(name, digest);
		this.transformations = transformations;
	}

	/**
	 * Adds a description to the signature scope
	 *
	 * @param description {@link String} to add
	 * @return {@link String}
	 */
	protected String addTransformationDescription(String description) {
		description += " with transformations.";
		return description;
	}

	/**
	 * Checks if the list of transforms is not empty
	 *
	 * @return TRUE if transforms are not empty, FALSE otherwise
	 */
	protected boolean isTransformationsNotEmpty() {
		return Utils.isCollectionNotEmpty(transformations);
	}

	@Override
	public List<String> getTransformations() {
		return transformations;
	}

}
