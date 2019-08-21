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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithCAdESManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestValidator.class);

	private final String signatureName;
	private final List<ManifestFile> manifestFiles;
	private final List<DSSDocument> signedDocuments;

	public ASiCEWithCAdESManifestValidator(String signatureName, List<DSSDocument> manifestDocuments, List<DSSDocument> signedDocuments) {
		this.signatureName = signatureName;
		this.manifestFiles = new ArrayList<ManifestFile>();
		if (Utils.isCollectionNotEmpty(manifestFiles)) {
			for (DSSDocument document : manifestDocuments) {
				ASiCEWithCAdESManifestParser asiceWithCAdESManifestParser = new ASiCEWithCAdESManifestParser(document);
				ManifestFile manifest = asiceWithCAdESManifestParser.getManifest();
				if (manifest != null) {
					manifestFiles.add(manifest);
				}
			}
		}
		this.signedDocuments = signedDocuments;
	}

	public ASiCEWithCAdESManifestValidator(List<ManifestFile> manifestFiles, List<DSSDocument> signedDocuments, String signatureName) {
		this.signatureName = signatureName;
		this.manifestFiles = manifestFiles;
		this.signedDocuments = signedDocuments;
	}

	public ManifestFile getLinkedManifest() {
		for (ManifestFile manifest : manifestFiles) {
			if (Utils.areStringsEqual(signatureName, manifest.getSignatureFilename())) {
				return manifest;
			}
		}
		return null;
	}

}
