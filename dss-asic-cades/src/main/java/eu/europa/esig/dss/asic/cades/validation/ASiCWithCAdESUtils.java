/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
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
		// empty
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
			DSSDocument linkedManifest = ASiCManifestParser.getLinkedManifest(extractResult.getManifestDocuments(), signatureFilename);
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
	 * @deprecated since DSS 6.3. Please use {@code ASiCUtils#isCoveredByManifest} method instead.
	 */
	@Deprecated
	public static boolean isCoveredByManifest(List<DSSDocument> manifestDocuments, String filename) {
		return ASiCUtils.isCoveredByManifest(manifestDocuments, filename);
	}

}
