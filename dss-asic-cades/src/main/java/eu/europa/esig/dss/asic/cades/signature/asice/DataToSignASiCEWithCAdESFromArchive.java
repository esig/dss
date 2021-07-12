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
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.SigningOperation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A class to generate a DataToSign with ASiC-E with CAdES from an existing archive
 */
public class DataToSignASiCEWithCAdESFromArchive extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	/** The original ASiC container */
	private final DSSDocument asicContainer;

	/** The list of signed documents */
	private final List<DSSDocument> signedDocuments;

	/** The list of signature documents */
	private final List<DSSDocument> embeddedSignatures;

	/** The list of manifest documents */
	private final List<DSSDocument> embeddedManifests;

	/** The list of archive manifest documents */
	private final List<DSSDocument> embeddedArchiveManifests;

	/** The list of timestamp documents */
	private final List<DSSDocument> embeddedTimestamps;

	/** The cached to be signed document */
	private DSSDocument toBeSigned;

	/**
	 * The default constructor
	 *
	 * @param operation {@link SigningOperation} to perform
	 * @param extractionResult {@link ASiCExtractResult} of an ASiC container to sign
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 */
	public DataToSignASiCEWithCAdESFromArchive(final SigningOperation operation,
											   final ASiCExtractResult extractionResult,
											   final ASiCWithCAdESCommonParameters parameters) {
		super(operation, parameters);
		this.asicContainer = extractionResult.getAsicContainer();
		this.signedDocuments = extractionResult.getSignedDocuments();
		this.embeddedSignatures = extractionResult.getSignatureDocuments();
		this.embeddedManifests = extractionResult.getManifestDocuments();
		this.embeddedArchiveManifests = extractionResult.getArchiveManifestDocuments();
		this.embeddedTimestamps = extractionResult.getTimestampDocuments();
	}

	@Override
	public DSSDocument getAsicContainer() {
		return asicContainer;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(embeddedSignatures);
	}

	@Override
	public String getTimestampFilename() {
		return getTimestampFileName(embeddedTimestamps);
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(signedDocuments, embeddedSignatures, embeddedTimestamps, embeddedManifests);
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
		List<DSSDocument> manifests = new ArrayList<>(embeddedManifests);
		manifests.add(getToBeSigned());
		return manifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return embeddedSignatures;
	}

	@Override
	public List<DSSDocument> getArchiveManifestFiles() {
		return embeddedArchiveManifests;
	}

	@Override
	public List<DSSDocument> getTimestamps() {
		return embeddedTimestamps;
	}

}
