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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Class containing utils methods for dealing with ASiC with CAdES container
 *
 */
public class ASiCWithCAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESUtils.class);

	/** The default Archive Manifest filename */
	public static final String DEFAULT_ARCHIVE_MANIFEST_FILENAME = ASiCUtils.META_INF_FOLDER +
			ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + ASiCUtils.XML_EXTENSION;

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
		if (ASiCContainerType.ASiC_S.equals(type) && extractResult.getRootLevelSignedDocuments().size() == 1) {
			return extractResult.getRootLevelSignedDocuments().iterator().next(); // Collection size should be equal 1

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
		LOG.warn("Unable to extract a signed document. Reason : Unknown asic container type.");
		return null;
	}
	
	/**
	 * Checks if a document (e.g. a signature) with the given filename is covered by a manifest
	 * 
	 * @param manifestDocuments a list of manifest {@link DSSDocument}s extracted from the archive
	 * @param filename {@link String} a filename of a document to check
	 * @return TRUE if the document is covered by a manifest, FALSE otherwise
	 */
	public static boolean isCoveredByManifest(List<DSSDocument> manifestDocuments, String filename) {
		if (Utils.isCollectionNotEmpty(manifestDocuments)) {
			for (DSSDocument archiveManifest : manifestDocuments) {
				ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(archiveManifest);
				for (ManifestEntry entry : manifestFile.getEntries()) {
					if (filename != null && filename.equals(entry.getFileName())) {
						return true;
					}
				}
			}
		}
		return false;
	}

}
