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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * An abstract class to generate a DataToSign with ASiC-E with CAdES
 */
public abstract class AbstractDataToSignASiCEWithCAdES {

	/** The default signature filename */
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = ASiCUtils.META_INF_FOLDER + "signature001.p7s";

	/** The default timestamp filename */
	private static final String ZIP_ENTRY_ASICE_METAINF_TIMESTAMP = ASiCUtils.META_INF_FOLDER + "timestamp001.tst";

	/** The SigningOperation to perform */
	private final SigningOperation operation;

	/** The parameters to use */
	private final ASiCWithCAdESCommonParameters parameters;

	/**
	 * The default constructor
	 *
	 * @param operation {@link SigningOperation} to perform
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 */
	protected AbstractDataToSignASiCEWithCAdES(final SigningOperation operation, final ASiCWithCAdESCommonParameters parameters) {
		this.operation = operation;
		this.parameters = parameters;
	}

	/**
	 * Generates an ASiC Manifest document to sign
	 *
	 * @param documents a ist of {@link DSSDocument}s to sign
	 * @param signatures a list of {@link DSSDocument} signatures
	 * @param timestamps a list of {@link DSSDocument} timestamps
	 * @param manifests a list of {@link DSSDocument} manifests
	 * @return {@link DSSDocument} representing an ASiC-E manifest
	 */
	protected DSSDocument getASiCManifest(List<DSSDocument> documents,
										  List<DSSDocument> signatures, List<DSSDocument> timestamps,
										  List<DSSDocument> manifests) {

		String uri = null;
		if (SigningOperation.SIGN == operation) {
			uri = getSignatureFileName(signatures);
		} else {
			uri = getTimestampFileName(timestamps);
		}

		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(
				operation, documents, parameters.getDigestAlgorithm(), uri);
		String newManifestName = ASiCUtils.getNextASiCManifestName(ASiCUtils.ASIC_MANIFEST_FILENAME, manifests);

		return DomUtils.createDssDocumentFromDomDocument(manifestBuilder.build(), newManifestName);
	}

	/**
	 * Generates and returns a signature filename
	 *
	 * @param existingSignatures a list of {@link DSSDocument} signatures from the container
	 * @return {@link String} signature filename
	 */
	protected String getSignatureFileName(List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(parameters.aSiC().getSignatureFileName())) {
			return ASiCUtils.META_INF_FOLDER + parameters.aSiC().getSignatureFileName();
		}

		int num = Utils.collectionSize(existingSignatures) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", ASiCUtils.getPadNumber(num));
	}

	/**
	 * Generates and returns a timestamp filename
	 *
	 * @param existingTimestamps a list of {@link DSSDocument} timestamps from the container
	 * @return {@link String} timestamp filename
	 */
	protected String getTimestampFileName(List<DSSDocument> existingTimestamps) {
		int num = Utils.collectionSize(existingTimestamps) + 1;
		return ZIP_ENTRY_ASICE_METAINF_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
	}

}
