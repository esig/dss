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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.validation.ASiCManifestValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;

import java.util.List;

/**
 * This class validates a manifest
 *
 * @deprecated since DSS 5.13. Please use
 * 			   {@code eu.europa.esig.dss.asic.common.validation.ASiCManifestValidator} class instead.
 */
@Deprecated
public class ASiCEWithCAdESManifestValidator {

	/** Manifest validator */
	private final ASiCManifestValidator manifestValidator;

	/**
	 * The default constructor
	 *
	 * @param manifest {@link ManifestFile}
	 * @param signedDocuments a list of {@link DSSDocument}s
	 * @deprecated since DSS 5.13. Please use {@code new ASiCManifestValidator(manifest, signedDocuments)} instead
	 */
	@Deprecated
	public ASiCEWithCAdESManifestValidator(final ManifestFile manifest, final List<DSSDocument> signedDocuments) {
		this.manifestValidator = new ASiCManifestValidator(manifest, signedDocuments);
	}
	
	/**
	 * Validates the manifest entries
	 * @return list of validated {@link ManifestEntry}s
	 * @deprecated since DSS 5.13. Please use {@code ASiCManifestValidator.validateEntries()} instead.
	 */
	@Deprecated
	public List<ManifestEntry> validateEntries() {
		return manifestValidator.validateEntries();
	}

}
