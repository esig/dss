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
package eu.europa.esig.dss.asic.cades.signature.asice;

import java.util.List;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractDataToSignASiCEWithCAdES {

	private static final String META_INF = "META-INF/";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	protected DSSDocument getASiCManifest(List<DSSDocument> documents, List<DSSDocument> signatures, List<DSSDocument> manifests,
			ASiCWithCAdESSignatureParameters parameters) {
		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(documents, parameters.getDigestAlgorithm(),
				getSignatureFileName(parameters.aSiC(), signatures));

		return DomUtils.createDssDocumentFromDomDocument(manifestBuilder.build(), getASiCManifestFilename(manifests));
	}

	protected String getSignatureFileName(final ASiCParameters asicParameters, List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}

		int num = Utils.collectionSize(existingSignatures) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", ASiCUtils.getPadNumber(num));
	}

	private String getASiCManifestFilename(List<DSSDocument> existingManifests) {
		String suffix = Utils.isCollectionEmpty(existingManifests) ? Utils.EMPTY_STRING : String.valueOf(existingManifests.size());
		return META_INF + "ASiCManifest" + suffix + ".xml";
	}

}
