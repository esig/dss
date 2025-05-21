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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCSignatureExtensionHelper;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;

import java.util.Collections;
import java.util.List;

/**
 * The class contains useful methods for ASiC with CAdES counter signature creation
 */
public class ASiCWithCAdESSignatureExtensionHelper extends ASiCSignatureExtensionHelper {

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC with CAdES container
	 */
	protected ASiCWithCAdESSignatureExtensionHelper(DSSDocument asicContainer) {
		super(asicContainer);
	}

	@Override
	protected DefaultASiCContainerExtractor getASiCContainerExtractor() {
		return new ASiCWithCAdESContainerExtractor(asicContainer);
	}

	@Override
	protected DocumentAnalyzer getDocumentAnalyzer(DSSDocument signatureDocument) {
		return new CMSDocumentAnalyzer(signatureDocument);
	}

	@Override
	public List<DSSDocument> getDetachedDocuments(String signatureFilename) {
		DSSDocument signedDocument = ASiCWithCAdESUtils.getSignedDocument(getAsicContent(), signatureFilename);
		if (signedDocument != null) {
			return Collections.singletonList(signedDocument);
		}
		return Collections.emptyList();
	}
	
	@Override
	public ManifestFile getManifestFile(String signatureFilename) {
		DSSDocument signatureManifest = ASiCManifestParser.getLinkedManifest(
				getAsicContent().getAllManifestDocuments(), signatureFilename);
		if (signatureManifest != null) {
			return ASiCManifestParser.getManifestFile(signatureManifest);
		}
		return null;
	}
	
	@Override
	protected void checkSignatureExtensionPossible(DSSDocument signatureDocument) {
		super.checkSignatureExtensionPossible(signatureDocument);
		
		if (ASiCWithCAdESUtils.isCoveredByManifest(getAsicContent().getAllManifestDocuments(), signatureDocument.getName())) {
			throw new IllegalInputException(String.format("The modification of the signature is not possible! "
					+ "Reason : a signature with a filename '%s' is covered by another manifest.", signatureDocument.getName()));
		}
	}

}
