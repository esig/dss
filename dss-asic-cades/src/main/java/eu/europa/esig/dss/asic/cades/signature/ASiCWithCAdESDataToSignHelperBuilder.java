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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.asice.DataToSignASiCEWithCAdESHelper;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromArchive;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromFiles;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCDataToSignHelperBuilder;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;

/**
 * Builds a relevant {@code GetDataToSignASiCWithCAdESHelper} for ASiC with CAdES dataToSign creation
 *
 */
public abstract class ASiCWithCAdESDataToSignHelperBuilder extends AbstractASiCDataToSignHelperBuilder {

	/**
	 * Defines rules for filename creation for new manifest files.
	 */
	protected final ASiCWithCAdESFilenameFactory asicFilenameFactory;

	/**
	 * Default constructor
	 *
	 * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
	 */
	protected ASiCWithCAdESDataToSignHelperBuilder(final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
		this.asicFilenameFactory = asicFilenameFactory;
	}

	/**
	 * This method is used to create a {@code GetDataToSignASiCWithCAdESHelper} from an {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 * @return {@link GetDataToSignASiCWithCAdESHelper}
	 */
	public GetDataToSignASiCWithCAdESHelper build(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters.aSiC());

		if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())
				|| Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) {
			ASiCContainerType currentContainerType = asicContent.getContainerType();

			boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
			if (asice && ASiCContainerType.ASiC_E.equals(currentContainerType)) {
				DSSDocument manifestDocument = createManifestDocument(asicContent, parameters);
				return new DataToSignASiCEWithCAdESHelper(asicContent, manifestDocument);

			} else if (!asice && ASiCContainerType.ASiC_S.equals(currentContainerType)) {
				if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
						Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) {
					return new DataToSignASiCSWithCAdESFromArchive(asicContent);
				} else {
					return new DataToSignASiCSWithCAdESFromFiles(asicContent);
				}

			} else {
				throw new UnsupportedOperationException(
						String.format("Original container type '%s' vs parameter : '%s'", currentContainerType,
								parameters.aSiC().getContainerType()));
			}
		}
		return fromFiles(asicContent, parameters);
	}

	private GetDataToSignASiCWithCAdESHelper fromFiles(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
		if (ASiCUtils.isASiCE(parameters.aSiC())) {
			asicContent.setContainerType(ASiCContainerType.ASiC_E);
			DSSDocument manifestDocument = createManifestDocument(asicContent, parameters);
			return new DataToSignASiCEWithCAdESHelper(asicContent, manifestDocument);

		} else {
			asicContent.setContainerType(ASiCContainerType.ASiC_S);
			DSSDocument asicsSignedDocument = getASiCSSignedDocument(
					asicContent.getSignedDocuments(), parameters.getZipCreationDate());
			asicContent.setSignedDocuments(Collections.singletonList(asicsSignedDocument));
			return new DataToSignASiCSWithCAdESFromFiles(asicContent);
		}
	}

	private DSSDocument createManifestDocument(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
		return getManifestBuilder(asicContent, parameters).build();
	}

	/**
	 * This method returns a {@code ASiCEWithCAdESManifestBuilder} to be used for a signed/timestamped manifest creation
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 * @return {@link ASiCEWithCAdESManifestBuilder}
	 */
	protected abstract ASiCEWithCAdESManifestBuilder getManifestBuilder(ASiCContent asicContent,
																		ASiCWithCAdESCommonParameters parameters);

	@Override
	protected String getDataPackageName(ASiCContent asicContent) {
		return asicFilenameFactory.getDataPackageFilename(asicContent);
	}

}
