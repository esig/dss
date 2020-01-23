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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.SigningOperation;

public class DataToSignASiCEWithCAdESFromArchive extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final SigningOperation operation;
	private final List<DSSDocument> signedDocuments;
	private final List<DSSDocument> existingSignatures;
	private final List<DSSDocument> existingManifests;
	private final List<DSSDocument> existingArchiveManifests;
	private final List<DSSDocument> existingTimestamps;
	private final ASiCWithCAdESCommonParameters parameters;

	private DSSDocument toBeSigned;

	public DataToSignASiCEWithCAdESFromArchive(SigningOperation operation, final ASiCExtractResult extractionResult,
			final ASiCWithCAdESCommonParameters parameters) {
		this.operation = operation;
		this.signedDocuments = extractionResult.getSignedDocuments();
		this.existingSignatures = extractionResult.getSignatureDocuments();
		this.existingManifests = extractionResult.getManifestDocuments();
		this.existingArchiveManifests = extractionResult.getArchiveManifestDocuments();
		this.existingTimestamps = extractionResult.getTimestampDocuments();
		this.parameters = parameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(parameters.aSiC(), existingSignatures);
	}

	@Override
	public String getTimestampFilename() {
		return getTimestampFileName(existingTimestamps);
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(operation, signedDocuments, existingSignatures, existingTimestamps, existingManifests, parameters);
		}
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		List<DSSDocument> manifests = new ArrayList<>(existingManifests);
		manifests.add(getToBeSigned());
		return manifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return existingSignatures;
	}

	@Override
	public List<DSSDocument> getArchiveManifestFiles() {
		return existingArchiveManifests;
	}

	@Override
	public List<DSSDocument> getTimestamps() {
		return existingTimestamps;
	}

}
