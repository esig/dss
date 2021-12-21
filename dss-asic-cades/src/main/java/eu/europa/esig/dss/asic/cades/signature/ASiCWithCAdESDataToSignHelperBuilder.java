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
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.signature.asice.DataToSignASiCEWithCAdESHelper;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromArchive;
import eu.europa.esig.dss.asic.cades.signature.asics.DataToSignASiCSWithCAdESFromFiles;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCDataToSignHelperBuilder;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

/**
 * Builds a relevant {@code GetDataToSignASiCWithCAdESHelper} for ASiC with CAdES dataToSign creation
 */
public abstract class ASiCWithCAdESDataToSignHelperBuilder extends AbstractASiCDataToSignHelperBuilder {

	/**
	 * Builds a {@code GetDataToSignASiCWithCAdESHelper} from the given list of documents and defined parameters
	 *
	 * @param documents a list of {@link DSSDocument}s to get a helper from
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 * @return {@link GetDataToSignASiCWithCAdESHelper}
	 */
	public GetDataToSignASiCWithCAdESHelper build(List<DSSDocument> documents, ASiCWithCAdESCommonParameters parameters) {
		if (Utils.isCollectionNotEmpty(documents) && documents.size() == 1) {
			DSSDocument archiveDocument = documents.get(0);
			if (ASiCUtils.isZip(archiveDocument) && isASiCWithCAdESContainer(archiveDocument)) {
				return fromZipArchive(archiveDocument, parameters);
			}
		}
		return fromFiles(documents, parameters);
	}

	private boolean isASiCWithCAdESContainer(DSSDocument archiveDocument) {
		List<String> filenames = ZipUtils.getInstance().extractEntryNames(archiveDocument);
		return ASiCUtils.isAsicFileContent(filenames);
	}
	
	private GetDataToSignASiCWithCAdESHelper fromZipArchive(DSSDocument archiveDoc, ASiCWithCAdESCommonParameters parameters) {
		ASiCWithCAdESContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(archiveDoc);
		ASiCContent asicContent = extractor.extract();
		assertContainerTypeValid(asicContent);

		return buildFromASiCContent(asicContent, parameters);
	}

	/**
	 * This method is used to create a {@code GetDataToSignASiCWithCAdESHelper} from an {@code ASiCContent}
	 * ]
	 * @param asicContent {@link ASiCContent}
	 * @param parameters {@link ASiCWithCAdESCommonParameters}
	 * @return {@link GetDataToSignASiCWithCAdESHelper}
	 */
	public GetDataToSignASiCWithCAdESHelper buildFromASiCContent(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters.aSiC());

		if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())
				|| Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) {
			ASiCContainerType currentContainerType = asicContent.getContainerType();

			boolean asice = ASiCUtils.isASiCE(parameters.aSiC());
			if (asice && ASiCContainerType.ASiC_E.equals(currentContainerType)) {
				DSSDocument manifestDocument = createManifestDocument(asicContent, parameters);
				return new DataToSignASiCEWithCAdESHelper(asicContent, manifestDocument, parameters.aSiC());

			} else if (!asice && ASiCContainerType.ASiC_S.equals(currentContainerType)) {
				if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
						Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) {
					return new DataToSignASiCSWithCAdESFromArchive(asicContent, parameters.aSiC());
				} else {
					return new DataToSignASiCSWithCAdESFromFiles(asicContent, parameters.aSiC());
				}

			} else {
				throw new UnsupportedOperationException(
						String.format("Original container type '%s' vs parameter : '%s'", currentContainerType,
								parameters.aSiC().getContainerType()));
			}
		}
		return fromFiles(asicContent, parameters);
	}
	
	private GetDataToSignASiCWithCAdESHelper fromFiles(List<DSSDocument> documents, ASiCWithCAdESCommonParameters parameters) {
		assertDocumentNamesDefined(documents);

		ASiCContent asicContent = new ASiCContent();
		asicContent.setContainerType(parameters.aSiC().getContainerType());
		asicContent.setSignedDocuments(documents);
		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters.aSiC());

		return fromFiles(asicContent, parameters);
	}

	private GetDataToSignASiCWithCAdESHelper fromFiles(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
		if (ASiCUtils.isASiCE(parameters.aSiC())) {
			DSSDocument manifestDocument = createManifestDocument(asicContent, parameters);
			return new DataToSignASiCEWithCAdESHelper(asicContent, manifestDocument, parameters.aSiC());

		} else {
			DSSDocument asicsSignedDocument = getASiCSSignedDocument(asicContent.getSignedDocuments(),
					parameters.getZipCreationDate(), parameters.aSiC());
			asicContent.setSignedDocuments(Collections.singletonList(asicsSignedDocument));
			return new DataToSignASiCSWithCAdESFromFiles(asicContent, parameters.aSiC());
		}
	}

	private void assertContainerTypeValid(ASiCContent result) {
		if (ASiCUtils.filesContainSignatures(DSSUtils.getDocumentNames(result.getAllDocuments()))
				&& Utils.isCollectionEmpty(result.getSignatureDocuments())) {
			throw new UnsupportedOperationException("Container type doesn't match");
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

}
