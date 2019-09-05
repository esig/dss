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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithCAdESManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestValidator.class);

	private final ManifestFile manifest;
	private final List<DSSDocument> signedDocuments;

	public ASiCEWithCAdESManifestValidator(ManifestFile manifest, List<DSSDocument> signedDocuments) {
		Objects.requireNonNull(manifest, "ManifestFile must be defined!");
		this.manifest = manifest;
		this.signedDocuments = signedDocuments;
	}
	
	/**
	 * Validates the manifest entries
	 * @return list of validated {@link ManifestEntry}s
	 */
	public List<ManifestEntry> validateEntries() {
		List<ManifestEntry> manifestEntries = manifest.getEntries();
		if (signedDocuments == null) {
			// no signed data to validate on
			return manifestEntries;
		}
		for (ManifestEntry entry : manifestEntries) {
			
			if (entry.getDigest() != null) {
				for (DSSDocument signedDocument : signedDocuments) {
					
					if (entry.getFileName().equals(signedDocument.getName())) {
						entry.setFound(true);
						String computedDigest = signedDocument.getDigest(entry.getDigest().getAlgorithm());
						if (Arrays.equals(entry.getDigest().getValue(), Utils.fromBase64(computedDigest))) {
							entry.setIntact(true);
							
						} else {
							LOG.warn("Digest value doesn't match for signed data with name '{}'", entry.getFileName());
							LOG.warn("Expected : '{}'", Utils.toBase64(entry.getDigest().getValue()));
							LOG.warn("Computed : '{}'", computedDigest);
							
						}
						break;
						
					}
				}
				
			} else {
				LOG.warn("Digest is not defined for signed data with name '{}'", entry.getFileName());
				
			}
			
			if (!entry.isFound()) {
				LOG.warn("Signed data with name '{}' not found", entry.getFileName());
			}
			
		}
		
		return manifestEntries;
	}

}
