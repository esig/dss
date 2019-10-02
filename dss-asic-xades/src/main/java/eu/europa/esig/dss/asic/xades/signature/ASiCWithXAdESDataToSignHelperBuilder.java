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
package eu.europa.esig.dss.asic.xades.signature;

import java.util.List;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.asice.DataToSignASiCEWithXAdESFromArchive;
import eu.europa.esig.dss.asic.xades.signature.asice.DataToSignASiCEWithXAdESFromFiles;
import eu.europa.esig.dss.asic.xades.signature.asice.DataToSignOpenDocument;
import eu.europa.esig.dss.asic.xades.signature.asics.DataToSignASiCSWithXAdESFromArchive;
import eu.europa.esig.dss.asic.xades.signature.asics.DataToSignASiCSWithXAdESFromFiles;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;

public class ASiCWithXAdESDataToSignHelperBuilder {

	private ASiCWithXAdESDataToSignHelperBuilder() {
	}

	public static GetDataToSignASiCWithXAdESHelper getGetDataToSignHelper(List<DSSDocument> documents,
			ASiCWithXAdESSignatureParameters parameters) {

		BLevelParameters bLevel = parameters.bLevel();

		boolean zip = ASiCUtils.isArchive(documents);
		boolean signedAsic = ASiCUtils.isAsic(documents);
		boolean asice = ASiCUtils.isASiCE(parameters.aSiC());

		if (zip) {
			DSSDocument archiveDoc = documents.get(0);
			ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(archiveDoc);
			ASiCExtractResult extract = extractor.extract();
			
			boolean openDocument = ASiCUtils.isOpenDocument(extract.getMimeTypeDocument());
			if (openDocument) {
				return new DataToSignOpenDocument(extract.getOriginalDocuments(),
						extract.getSignatureDocuments(), extract.getManifestDocuments(), extract.getMimeTypeDocument(), extract.getRootContainer());
			} else if (signedAsic) {
				if (!ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(archiveDoc, ".xml")) {
					throw new UnsupportedOperationException("Container type doesn't match");
				}

				if (asice) {
					return new DataToSignASiCEWithXAdESFromArchive(extract.getOriginalDocuments(),
							extract.getSignatureDocuments(), extract.getManifestDocuments(), parameters.aSiC());
				} else {
					return new DataToSignASiCSWithXAdESFromArchive(extract.getSignatureDocuments(),
							extract.getOriginalDocuments(), parameters.aSiC());
				}
			} else {
				return fromFiles(documents, parameters, bLevel, asice);
			}
		} else {
			return fromFiles(documents, parameters, bLevel, asice);
		}
	}

	private static GetDataToSignASiCWithXAdESHelper fromFiles(List<DSSDocument> documents,
			ASiCWithXAdESSignatureParameters parameters, BLevelParameters bLevel, boolean asice) {
		if (asice) {
			return new DataToSignASiCEWithXAdESFromFiles(documents, parameters.aSiC());
		} else {
			return new DataToSignASiCSWithXAdESFromFiles(documents, bLevel.getSigningDate(), parameters.aSiC());
		}
	}

}
