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
import java.util.Objects;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class ASiCEWithCAdESTimestampValidator extends DetachedTimestampValidator {

	/* ASiCArchiveManifest */
	private final ManifestFile manifestFile;
	/* A list of original documents present in the container */
	private final List<DSSDocument> originalDocuments;

	/**
	 * Default constructor for ASiCE CAdES timestamp validator
	 * 
	 * @param timestamp
	 *                              {@link DSSDocument} the timestamp document file
	 * @param type
	 *                              {@link TimestampType} type of the timestamp
	 * @param validatedManifestFile
	 *                              a validated {@link ManifestFile}
	 * @param originalDocuments
	 *                              a list of original {@link DSSDocument}s present
	 *                              into the container
	 */
	public ASiCEWithCAdESTimestampValidator(DSSDocument timestamp, TimestampType type, ManifestFile validatedManifestFile,
			List<DSSDocument> originalDocuments) {
		super(timestamp, type);
		Objects.requireNonNull(validatedManifestFile, "The validated ManifestFile must be defined!");
		this.manifestFile = validatedManifestFile;
		this.originalDocuments = originalDocuments;
	}

	/**
	 * Returns the covered {@code ManifestFile}
	 * 
	 * @return {@link ManifestFile}
	 */
	public ManifestFile getCoveredManifest() {
		return manifestFile;
	}

	@Override
	public TimestampToken getTimestamp() {
		TimestampToken timestamp = super.getTimestamp();
		timestamp.setManifestFile(getCoveredManifest());
		timestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_DETACHED);
		timestamp.setTimestampScopes(getTimestampSignatureScopes());
		return timestamp;
	}

	@Override
	protected List<SignatureScope> getTimestampSignatureScopes() {
		List<SignatureScope> result = new ArrayList<>();
		result.add(new ManifestSignatureScope(manifestFile.getFilename(), DSSUtils.getDigest(getDefaultDigestAlgorithm(), getTimestampedData())));
		if (Utils.isCollectionNotEmpty(originalDocuments)) {
			for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
				for (DSSDocument document : originalDocuments) {
					if (Utils.areStringsEqual(manifestEntry.getFileName(), document.getName())) {
						result.add(new FullSignatureScope(manifestEntry.getFileName(), DSSUtils.getDigest(getDefaultDigestAlgorithm(), document)));
					}
				}
			}
		}
		return result;
	}

}
