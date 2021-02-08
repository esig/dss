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
package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a relevant {@code GetDataToSignASiCWithCAdESHelper} for ASiC container dataToSign creation
 */
public abstract class AbstractASiCDataToSignHelperBuilder {

	/** The default name for a detached file if one is not defined */
	private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	
	/**
	 * Checks if the document names are defined and adds them if needed
	 * 
	 * @param documents a list of {@link DSSDocument}
	 */
	protected void assertDocumentNamesDefined(List<DSSDocument> documents) {
		List<DSSDocument> unnamedDocuments = getDocumentsWithoutNames(documents);
		if (unnamedDocuments.size() == 1) {
			DSSDocument dssDocument = unnamedDocuments.iterator().next();
			dssDocument.setName(ZIP_ENTRY_DETACHED_FILE);
		} else {
			for (int ii = 0; ii < unnamedDocuments.size(); ii++) {
				DSSDocument dssDocument = unnamedDocuments.get(ii);
				dssDocument.setName(ZIP_ENTRY_DETACHED_FILE + "-" + ii);
			}
		}
	}
	
	private List<DSSDocument> getDocumentsWithoutNames(List<DSSDocument> documents) {
		List<DSSDocument> result = new ArrayList<>();
		for (DSSDocument document : documents) {
			if (Utils.isStringBlank(document.getName())) {
				result.add(document);
			}
		}
		return result;
	}

}
