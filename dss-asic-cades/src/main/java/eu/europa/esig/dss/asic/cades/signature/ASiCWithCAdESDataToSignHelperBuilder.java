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
package eu.europa.esig.dss.asic.cades.signature;

import java.util.List;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.asice.DataToSignASiCEWithCAdESFromArchive;
import eu.europa.esig.dss.asic.cades.signature.asice.DataToSignASiCEWithCAdESFromFiles;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromArchive;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromFiles;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;

public class ASiCWithCAdESDataToSignHelperBuilder {

	private ASiCWithCAdESDataToSignHelperBuilder() {
	}

	public static GetDataToSignASiCWithCAdESHelper getGetDataToSignHelper(List<DSSDocument> documents, ASiCWithCAdESSignatureParameters parameters) {

		BLevelParameters bLevel = parameters.bLevel();
		boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
		boolean asic = ASiCUtils.isAsic(documents);

		if (asic) {
			DSSDocument archiveDoc = documents.get(0);
			if (!ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(archiveDoc, ".p7s")) {
				throw new UnsupportedOperationException("Container type doesn't match");
			}

			ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(archiveDoc);
			ASiCExtractResult result = extractor.extract();
			if (asice) {
				return new DataToSignASiCEWithCAdESFromArchive(result, parameters);
			} else {
				return new DataToSignASiCSWithCAdESFromArchive(result, parameters.aSiC());
			}
		} else {
			if (asice) {
				return new DataToSignASiCEWithCAdESFromFiles(documents, parameters);
			} else {
				return new DataToSignASiCSWithCAdESFromFiles(documents, bLevel.getSigningDate(), parameters.aSiC());
			}
		}
	}
}
