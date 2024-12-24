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
package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains utils for OpenDocument processing
 */
public final class OpenDocumentSupportUtils {

	/** Defines the external data directory name */
	private static final String EXTERNAL_DATA = "external-data/";

	private OpenDocumentSupportUtils() {
	}

	/**
	 * ODF 1.2 ch 3.16
	 * 
	 * An OpenDocument document that is stored in a package may have one or more
	 * digital signatures applied to the package.
	 * 
	 * Document signatures shall be stored in a file called
	 * META-INF/documentsignatures.xml in the package as described in section 3.5 of
	 * the OpenDocument specification part 3. Document signatures shall contain a
	 * {@code <ds:Reference>} element for each file within the package, with the
	 * exception that {@code <ds:Reference>} elements for the
	 * META-INF/documentsignatures.xml file containing the signature, and any files
	 * contained in the package whose relative path starts with "external-data/"
	 * should be omitted.
	 *
	 * @param asicContent {@link ASiCContent}
	 * @return the list of covered documents
	 */
	public static List<DSSDocument> getOpenDocumentCoverage(ASiCContent asicContent) {
		List<DSSDocument> docs = new ArrayList<>();
		docs.addAll(asicContent.getSignedDocuments());
		docs.addAll(asicContent.getManifestDocuments());
		docs.addAll(asicContent.getArchiveManifestDocuments());
		docs.addAll(asicContent.getTimestampDocuments());
		docs.addAll(asicContent.getUnsupportedDocuments());
		docs.add(asicContent.getMimeTypeDocument());

		List<DSSDocument> result = new ArrayList<>();
		for (DSSDocument doc : docs) {
			if (!isExternalDataDocument(doc)) {
				result.add(doc);
			}
		}

		return result;
	}

	/**
	 * Verifies whether the document is located within "external-data/" folder within the archive
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document is within the "external-data/" folder, FALSE otherwise
	 */
	public static boolean isExternalDataDocument(DSSDocument document) {
		return document.getName() != null && document.getName().startsWith(EXTERNAL_DATA);
	}

}
