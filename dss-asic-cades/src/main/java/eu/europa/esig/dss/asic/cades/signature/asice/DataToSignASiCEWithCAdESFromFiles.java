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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.SigningOperation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A class to generate a DataToSign with ASiC-E with CAdES from a files to be signed
 */
public class DataToSignASiCEWithCAdESFromFiles extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	/** The list of documents to be signed */
	private final List<DSSDocument> filesToBeSigned;

	/** The cached ToBeSigned document */
	private DSSDocument toBeSigned;

	/**
	 * The default constructor
	 *
	 * @param operation {@link SigningOperation} to perform
	 * @param filesToBeSigned a list of {@link DSSDocument} to sign
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 */
	public DataToSignASiCEWithCAdESFromFiles(final SigningOperation operation, final List<DSSDocument> filesToBeSigned,
											 final ASiCWithCAdESCommonParameters parameters) {
		super(operation, parameters);
		this.filesToBeSigned = filesToBeSigned;
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(filesToBeSigned, Collections.<DSSDocument>emptyList(),
					Collections.<DSSDocument>emptyList(), Collections.<DSSDocument>emptyList());
		}
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(Collections.<DSSDocument> emptyList());
	}

	@Override
	public String getTimestampFilename() {
		return getTimestampFileName(Collections.<DSSDocument>emptyList());
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return filesToBeSigned;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return Arrays.asList(getToBeSigned());
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return new ArrayList<>();
	}

	@Override
	public List<DSSDocument> getArchiveManifestFiles() {
		// not supported
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getTimestamps() {
		// not supported
		return Collections.emptyList();
	}

}
