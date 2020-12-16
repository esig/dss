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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import eu.europa.esig.dss.xades.validation.scope.XAdESSignatureScopeFinder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class is an implementation to validate ASiC containers with XAdES signature(s)
 * 
 */
public class ASiCContainerWithXAdESValidator extends AbstractASiCContainerValidator {

	/**
	 * The empty constructor
	 */
	ASiCContainerWithXAdESValidator() {
		super(null);
	}

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} to be validated
	 */
	public ASiCContainerWithXAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer, new XAdESSignatureScopeFinder());
		extractEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		if (ASiCUtils.isZip(dssDocument)) {
			List<String> filenames = ZipUtils.getInstance().extractEntryNames(dssDocument);
			return !ASiCUtils.isASiCWithCAdES(filenames);
		}
		return false;
	}

	@Override
	protected AbstractASiCContainerExtractor getContainerExtractor() {
		return new ASiCWithXAdESContainerExtractor(document);
	}

	@Override
	protected List<DocumentValidator> getSignatureValidators() {
		if (signatureValidators == null) {
			signatureValidators = new ArrayList<>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				XMLDocumentValidator xadesValidator = new XMLDocumentValidator(signature);
				xadesValidator.setCertificateVerifier(certificateVerifier);
				xadesValidator.setProcessExecutor(processExecutor);
				xadesValidator.setSignaturePolicyProvider(getSignaturePolicyProvider());

				if (ASiCUtils.isOpenDocument(getMimeTypeDocument())) {
					xadesValidator.setDetachedContents(OpenDocumentSupportUtils.getOpenDocumentCoverage(extractResult));
				} else if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
					xadesValidator.setDetachedContents(getSignedDocuments());
					xadesValidator.setContainerContents(getArchiveDocuments());
				} else {
					xadesValidator.setDetachedContents(getAllDocuments());
				}

				signatureValidators.add(xadesValidator);
			}
		}
		return signatureValidators;
	}

	@Override
	protected List<ManifestFile> getManifestFilesDescriptions() {
		List<ManifestFile> descriptions = new ArrayList<>();
		List<DSSDocument> signatureDocuments = getSignatureDocuments();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		// All signatures use the same file : manifest.xml
		for (DSSDocument signatureDoc : signatureDocuments) {
			for (DSSDocument manifestDoc : manifestDocuments) {
				ASiCEWithXAdESManifestParser manifestParser = new ASiCEWithXAdESManifestParser(signatureDoc, manifestDoc);
				descriptions.add(manifestParser.getManifest());
			}
		}
		return descriptions;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		List<DSSDocument> potentials;
		if (ASiCUtils.isOpenDocument(getMimeTypeDocument())) {
			potentials = OpenDocumentSupportUtils.getOpenDocumentCoverage(extractResult);
		} else {
			potentials = getAllDocuments();
		}
		for (final DSSDocument signature : getSignatureDocuments()) {
			XMLDocumentValidator xadesValidator = new XMLDocumentValidator(signature);
			xadesValidator.setCertificateVerifier(certificateVerifier);
			xadesValidator.setDetachedContents(potentials);
			List<DSSDocument> retrievedDocs = xadesValidator.getOriginalDocuments(signatureId);
			if (Utils.isCollectionNotEmpty(retrievedDocs)) {
				return extractArchiveDocuments(retrievedDocs);
			}
		}
		return Collections.emptyList();
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		XAdESSignature xadesignature = (XAdESSignature) advancedSignature;
		List<DSSDocument> retrievedDocs = XAdESSignatureUtils.getSignerDocuments(xadesignature);
		if (Utils.isCollectionNotEmpty(retrievedDocs)) {
			return extractArchiveDocuments(retrievedDocs);
		}
		return Collections.emptyList();
	}
	
	private List<DSSDocument> extractArchiveDocuments(List<DSSDocument> retrievedDocs) {
		if (Utils.isCollectionNotEmpty(getArchiveDocuments())) {
			return getArchiveDocuments();
		}
		if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
			return getSignedDocumentsASiCS(retrievedDocs);
		}
		return retrievedDocs;
	}

}
