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
package eu.europa.esig.dss.asic.xades.signature.asice;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;

public class DataToSignASiCEWithXAdESFromArchive extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	private final List<DSSDocument> signedDocuments;
	private final List<DSSDocument> existingSignatures;
	private final List<DSSDocument> existingManifests;
	private final ASiCParameters asicParameters;

	public DataToSignASiCEWithXAdESFromArchive(List<DSSDocument> signedDocuments, List<DSSDocument> existingSignatures, List<DSSDocument> existingManifests,
			ASiCParameters asicParameters) {
		this.signedDocuments = signedDocuments;
		this.existingSignatures = existingSignatures;
		this.existingManifests = existingManifests;
		this.asicParameters = asicParameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters, existingSignatures);
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return signedDocuments;
	}

	@Override
	public DSSDocument getExistingSignature() {
		return null;
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return existingManifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return existingSignatures;
	}

}
