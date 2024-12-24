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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestValidator;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerAnalyzer;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class is an implementation to validate ASiC containers with XAdES signature(s)
 * 
 */
public class ASiCContainerWithXAdESAnalyzer extends AbstractASiCContainerAnalyzer {

	/**
	 * The empty constructor
	 */
	ASiCContainerWithXAdESAnalyzer() {
		super();
	}

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} to be validated
	 */
	public ASiCContainerWithXAdESAnalyzer(final DSSDocument asicContainer) {
		super(asicContainer);
	}

	/**
	 * The constructor from {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 */
	public ASiCContainerWithXAdESAnalyzer(final ASiCContent asicContent) {
		super(asicContent);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		if (ASiCUtils.isZip(dssDocument)) {
			List<String> filenames = ZipUtils.getInstance().extractEntryNames(dssDocument);
			if (ASiCUtils.isASiCWithXAdES(filenames)) {
				return true;
			}
			return !ASiCUtils.isASiCWithCAdES(filenames);
		}
		return false;
	}

	@Override
	public boolean isSupported(ASiCContent asicContent) {
		List<String> entryNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
		return !ASiCUtils.isASiCWithCAdES(entryNames);
	}

	@Override
	protected DefaultASiCContainerExtractor getContainerExtractor() {
		return new ASiCWithXAdESContainerExtractor(document);
	}

	@Override
	protected List<DocumentAnalyzer> getSignatureAnalyzers() {
		if (signatureValidators == null) {
			signatureValidators = new ArrayList<>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				XMLDocumentAnalyzer documentAnalyzer = new XMLDocumentAnalyzer(signature);
				documentAnalyzer.setCertificateVerifier(certificateVerifier);
				documentAnalyzer.setSignaturePolicyProvider(getSignaturePolicyProvider());

				if (ASiCUtils.isOpenDocument(getMimeTypeDocument())) {
					documentAnalyzer.setDetachedContents(OpenDocumentSupportUtils.getOpenDocumentCoverage(asicContent));
				} else if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
					documentAnalyzer.setDetachedContents(getSignedDocuments());
					documentAnalyzer.setContainerContents(getArchiveDocuments());
				} else {
					documentAnalyzer.setDetachedContents(getAllDocuments());
				}

				signatureValidators.add(documentAnalyzer);
			}
		}
		return signatureValidators;
	}

	@Override
	protected List<ManifestFile> getManifestFilesDescriptions() {
		final List<ManifestFile> descriptions = new ArrayList<>();

		List<DSSDocument> signatureDocuments = getSignatureDocuments();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		// All signatures use the same file : manifest.xml
		for (DSSDocument signatureDoc : signatureDocuments) {
			for (DSSDocument manifestDoc : manifestDocuments) {
				ASiCEWithXAdESManifestParser manifestParser = new ASiCEWithXAdESManifestParser(signatureDoc, manifestDoc);
				descriptions.add(manifestParser.getManifest());
			}
		}

		List<DSSDocument> evidenceRecordManifestDocuments = getEvidenceRecordManifestDocuments();
		for (DSSDocument manifestDocument : evidenceRecordManifestDocuments) {
			ManifestFile manifestFile = ASiCManifestParser.getManifestFile(manifestDocument);
			if (manifestFile != null) {
				manifestFile.setManifestType(ASiCManifestTypeEnum.EVIDENCE_RECORD);
				ASiCManifestValidator manifestValidator = new ASiCManifestValidator(manifestFile, getAllDocuments());
				manifestValidator.validateEntries();
				descriptions.add(manifestFile);
			}
		}

		return descriptions;
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		XAdESSignature xadesSignature = (XAdESSignature) advancedSignature;
		List<DSSDocument> retrievedDocs = XAdESSignatureUtils.getSignerDocuments(xadesSignature);
		if (Utils.isCollectionNotEmpty(retrievedDocs)) {
			return extractArchiveDocuments(retrievedDocs);
		}
		return Collections.emptyList();
	}
	
	private List<DSSDocument> extractArchiveDocuments(List<DSSDocument> retrievedDocs) {
		if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
			return getSignedDocumentsASiCS(retrievedDocs);
		}
		return retrievedDocs;
	}

}
