/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCDataToSignHelperBuilder;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.asice.ASiCEWithXAdESManifestBuilder;
import eu.europa.esig.dss.asic.xades.signature.asice.DataToSignASiCEWithXAdESHelper;
import eu.europa.esig.dss.asic.xades.signature.asice.DataToSignOpenDocumentHelper;
import eu.europa.esig.dss.asic.xades.signature.asics.DataToSignASiCSWithXAdESHelper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;

/**
 * Builds a relevant {@code GetDataToSignASiCWithXAdESHelper} for ASiC with XAdES dataToSign creation
 */
public class ASiCWithXAdESDataToSignHelperBuilder extends AbstractASiCDataToSignHelperBuilder {

	/**
	 * Defines rules for filename creation for new data package file.
	 */
	protected final ASiCWithXAdESFilenameFactory asicFilenameFactory;

	/**
	 * Default constructor
	 *
	 * @param asicFilenameFactory {@link ASiCWithXAdESFilenameFactory}
	 */
	public ASiCWithXAdESDataToSignHelperBuilder(final ASiCWithXAdESFilenameFactory asicFilenameFactory) {
		this.asicFilenameFactory = asicFilenameFactory;
	}

	/**
	 * This method is used to create a {@code GetDataToSignASiCWithXAdESHelper} from an {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param parameters {@link ASiCWithXAdESSignatureParameters}
	 * @return {@link GetDataToSignASiCWithXAdESHelper}
	 */
	public GetDataToSignASiCWithXAdESHelper build(ASiCContent asicContent,
												  ASiCWithXAdESSignatureParameters parameters) {
		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters.aSiC());

		if (ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument())) {
			return new DataToSignOpenDocumentHelper(asicContent);
		}

		// if ASiC with XAdES (no detached timestamps are allowed)
		if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())) {

			ASiCContainerType currentContainerType = asicContent.getContainerType();

			boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
			if (asice && ASiCContainerType.ASiC_E.equals(currentContainerType)) {
				return new DataToSignASiCEWithXAdESHelper(asicContent);
			} else if (!asice && ASiCContainerType.ASiC_S.equals(currentContainerType)) {
				return new DataToSignASiCSWithXAdESHelper(asicContent);
			} else {
				throw new UnsupportedOperationException(
						String.format("Original container type '%s' vs parameter : '%s'", currentContainerType,
								parameters.aSiC().getContainerType()));
			}

		}

		return fromFiles(asicContent, parameters);
	}

	private GetDataToSignASiCWithXAdESHelper fromFiles(ASiCContent asicContent, ASiCWithXAdESSignatureParameters parameters) {
		if (ASiCUtils.isASiCE(parameters.aSiC())) {
			DSSDocument asicManifest = createASiCManifest(asicContent);
			asicContent.getManifestDocuments().add(asicManifest);
			return new DataToSignASiCEWithXAdESHelper(asicContent);

		} else {
			DSSDocument asicsSignedDocument = getASiCSSignedDocument(
					asicContent.getSignedDocuments(), parameters.bLevel().getSigningDate());
			asicContent.setSignedDocuments(Collections.singletonList(asicsSignedDocument));
			return new DataToSignASiCSWithXAdESHelper(asicContent);
		}
	}

	/**
	 * Returns the ASiC Manifest
	 *
	 * @param asicContent {@link ASiCContent} representing the container
	 * @return {@link DSSDocument} manifest
	 */
	private DSSDocument createASiCManifest(ASiCContent asicContent) {
		return new ASiCEWithXAdESManifestBuilder().setDocuments(asicContent.getSignedDocuments())
				.setManifestFilename(asicFilenameFactory.getManifestFilename(asicContent)).build();
	}

	@Override
	protected String getDataPackageName(ASiCContent asicContent) {
		return asicFilenameFactory.getDataPackageFilename(asicContent);
	}

}
