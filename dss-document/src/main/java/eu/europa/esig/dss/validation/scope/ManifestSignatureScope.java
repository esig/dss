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

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;

import java.util.List;

/**
 * The Signature Scope represents a Manifest document
 *
 */
public final class ManifestSignatureScope extends SignatureScopeWithTransformations {

	private static final long serialVersionUID = -5343386923285755160L;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} manifest filename
	 * @param digest {@link Digest}
	 */
	public ManifestSignatureScope(final String name, final Digest digest) {
		super(name, digest, null);
	}

	/**
	 * Constructor with a list of XML transformations (to be used for XAdES only)
	 *
	 * @param name {@link String} manifest filename
	 * @param digest {@link Digest}
	 * @param transformations a list of {@link String} transforms definitions
	 */
	public ManifestSignatureScope(final String name, final Digest digest, final List<String> transformations) {
		super(name, digest, transformations);
	}

    @Override
    public String getDescription() {
        return "Manifest document";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
