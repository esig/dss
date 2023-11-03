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

import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;

import java.util.List;

/**
 * This class parses the manifest document and produces a {@code ManifestFile}
 *
 * @deprecated since DSS 5.13. Use {@code eu.europa.esig.dss.asic.common.validation.ASiCManifestParser} class instead.
 */
@Deprecated
public class ASiCWithCAdESManifestParser {

	/**
	 * Default constructor
	 */
	private ASiCWithCAdESManifestParser() {
		// empty
	}

	/**
	 * Parses and converts {@code DSSDocument} to {@code ManifestFile}
	 *
	 * @param manifestDocument {@link DSSDocument} to parse
	 * @return {@link ManifestFile}
	 * @deprecated since DSS 5.13. Use {@code ASiCManifestParser.getManifestFile(manifestDocument)} instead.
	 */
	@Deprecated
	public static ManifestFile getManifestFile(DSSDocument manifestDocument) {
		return ASiCManifestParser.getManifestFile(manifestDocument);
	}
	
	/**
	 * Returns the relative manifests for the given signature name
	 *
	 * @param manifestDocuments list of found manifests {@link DSSDocument} in the container (candidates)
	 * @param signatureName {@link String} name of the signature to get related manifest for
	 * @return {@link DSSDocument} the related manifests
	 * @deprecated since DSS 5.13. Use {@code ASiCManifestParser.getLinkedManifest(manifestDocuments, signatureName)} instead.
	 */
	@Deprecated
	public static DSSDocument getLinkedManifest(List<DSSDocument> manifestDocuments, String signatureName) {
		return ASiCManifestParser.getLinkedManifest(manifestDocuments, signatureName);
	}

}
