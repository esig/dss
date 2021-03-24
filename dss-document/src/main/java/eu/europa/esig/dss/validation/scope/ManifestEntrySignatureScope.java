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

import java.util.List;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;

public class ManifestEntrySignatureScope extends SignatureScopeWithTransformations {
	
	private final String manifestName;

	/**
	 * Constructor with transformations (Used in XAdES)
	 * @param entryName {@link String} name of the manifest entry
	 * @param digest {@link Digest} of the manifest entry
	 * @param manifestName {@link String} name of the manifest containing the entry
	 * @param transformations list of {@link String}s transformations
	 */
	public ManifestEntrySignatureScope(final String entryName, final Digest digest, final String manifestName, 
			final List<String> transformations) {
		super(entryName, digest, transformations);
		this.manifestName = manifestName;
	}

	@Override
	public String getDescription() {
		String description;
		if (DomUtils.isElementReference(getName())) {
			description = String.format("The XML Manifest Entry with ID '%s' from a Manifest with name '%s'", getName(), manifestName);
		} else {
			description = String.format("The File Manifest Entry with name '%s' from a Manifest with name '%s'", getName(), manifestName);
		}
		return addTransformationIfNeeded(description);
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
