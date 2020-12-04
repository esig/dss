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

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A class to generate a DataToSign with ASiC-E with XAdES from a files to be signed
 */
public class DataToSignASiCEWithXAdESFromFiles extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	/** A list of files to be signed */
	private final List<DSSDocument> filesToBeSigned;

	/** Parameters to use */
	private final ASiCParameters asicParameters;

	/**
	 * The default constructor
	 *
	 * @param filesToBeSigned a list of {@link DSSDocument} to be signed
	 * @param asicParameters {@link ASiCParameters}
	 */
	public DataToSignASiCEWithXAdESFromFiles(List<DSSDocument> filesToBeSigned, ASiCParameters asicParameters) {
		this.filesToBeSigned = filesToBeSigned;
		this.asicParameters = asicParameters;
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return filesToBeSigned;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters, Collections.<DSSDocument> emptyList());
	}

	@Override
	public String getTimestampFilename() {
		throw new UnsupportedOperationException("Timestamp file cannot be added with ASiC-E + XAdES");
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return filesToBeSigned;
	}

	@Override
	public DSSDocument getExistingSignature() {
		return null;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return Arrays.asList(getASiCManifest(filesToBeSigned));
	}

	@Override
	public List<DSSDocument> getSignatures() {
		// new container
		return new ArrayList<>();
	}
	
	@Override
	public DSSDocument getRootDocument() {
		// No root container when using files
		return null;
	}

}
