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

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;

import java.util.List;

/**
 * Class containing utils methods for dealing with ASiC with CAdES container
 *
 */
public class ASiCWithCAdESUtils {

	/** The default Archive Manifest filename */
	public static final String DEFAULT_ARCHIVE_MANIFEST_FILENAME = ASiCUtils.META_INF_FOLDER +
			ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + ASiCUtils.XML_EXTENSION;

	/** The default signature filename */
	public static final String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = ASiCUtils.META_INF_FOLDER + "signature001.p7s";

	/** The default timestamp filename */
	public static final String ZIP_ENTRY_ASICE_METAINF_TIMESTAMP = ASiCUtils.META_INF_FOLDER + "timestamp001.tst";

	/**
	 * Utils class
	 */
	private ASiCWithCAdESUtils() {
	}
	
	/**
	 * Returns a list of signed documents by a signature with a given {@code signatureFilename}
	 * 
	 * @param extractResult {@link ASiCContent} representing an ASiC container extraction result
	 * @param signatureFilename {@link String} a filename of a signature to get extracted document for
	 * @return a list of {@link DSSDocument}s
	 */
	public static DSSDocument getSignedDocument(ASiCContent extractResult, String signatureFilename) {
		ASiCContainerType type = extractResult.getContainerType();
		if (ASiCContainerType.ASiC_S.equals(type) && extractResult.getSignedDocuments().size() == 1) {
			return extractResult.getSignedDocuments().iterator().next(); // Collection size should be equal 1
		} else if (ASiCContainerType.ASiC_E.equals(type)) {
			// the manifest file is signed
			List<DSSDocument> manifestDocuments = extractResult.getManifestDocuments();
			if (manifestDocuments.size() == 1) {
				return manifestDocuments.iterator().next();
			}
			// we need to check the manifest file and its digest
			DSSDocument linkedManifest = ASiCWithCAdESManifestParser.getLinkedManifest(extractResult.getManifestDocuments(), signatureFilename);
			if (linkedManifest != null) {
				return linkedManifest;
			} else {
				return null; // related manifest not found
			}
		}
		throw new IllegalInputException("Unable to extract a signed document. Reason : Unknown asic container type.");
	}
	
	/**
	 * Checks if a signature with the given filename is covered by a manifest
	 * 
	 * @param manifestDocuments a list of manifest {@link DSSDocument}s extracted from the archive
	 * @param signatureFilename {@link String} a filename of a signature to check
	 * @return TRUE if the signature is covered by a manifest, FALSE otherwise
	 */
	public static boolean isCoveredByManifest(List<DSSDocument> manifestDocuments, String signatureFilename) {
		if (Utils.isCollectionNotEmpty(manifestDocuments)) {
			for (DSSDocument archiveManifest : manifestDocuments) {
				ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(archiveManifest);
				for (ManifestEntry entry : manifestFile.getEntries()) {
					if (signatureFilename != null && signatureFilename.equals(entry.getFileName())) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Generates and returns a signature filename
	 *
	 * @param existingSignatures a list of {@link DSSDocument} signatures from the container
	 * @param expectedSignatureFileName {@link String} the desired signature filename (optional)
	 * @return {@link String} signature filename
	 */
	public static String getSignatureFileName(List<DSSDocument> existingSignatures, String expectedSignatureFileName) {
		if (Utils.isStringNotBlank(expectedSignatureFileName)) {
			assertSignatureNameIsValid(existingSignatures, expectedSignatureFileName);
			return ASiCUtils.META_INF_FOLDER + expectedSignatureFileName;

		} else {
			int num = Utils.collectionSize(existingSignatures) + 1;
			return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", ASiCUtils.getPadNumber(num));
		}
	}

	private static void assertSignatureNameIsValid(List<DSSDocument> existingSignatures, String signatureFileName) {
		if (DSSUtils.getDocumentNames(existingSignatures).contains(signatureFileName)) {
			throw new IllegalArgumentException(String.format("The signature file with name '%s' already exists " +
					"within the ASiC Container!", signatureFileName));
		}
	}

	/**
	 * Generates and returns a timestamp filename
	 *
	 * @param existingTimestamps a list of {@link DSSDocument} timestamps from the container
	 * @return {@link String} timestamp filename
	 */
	public static String getTimestampFileName(List<DSSDocument> existingTimestamps) {
		int num = Utils.collectionSize(existingTimestamps) + 1;
		return ZIP_ENTRY_ASICE_METAINF_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
	}

}
