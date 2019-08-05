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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * This class is an implementation to validate ASiC containers with XAdES signature(s)
 * 
 */
public class ASiCContainerWithXAdESValidator extends AbstractASiCContainerValidator {

	ASiCContainerWithXAdESValidator() {
		super(null);
	}

	public ASiCContainerWithXAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer);
		analyseEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return ASiCUtils.isASiCContainer(dssDocument) && ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(dssDocument, ".xml");
	}

	@Override
	protected AbstractASiCContainerExtractor getArchiveExtractor() {
		return new ASiCWithXAdESContainerExtractor(document);
	}

	@Override
	protected List<DocumentValidator> getValidators() {
		if (validators == null) {
			validators = new ArrayList<DocumentValidator>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				XMLDocumentForASiCValidator xadesValidator = new XMLDocumentForASiCValidator(signature);
				xadesValidator.setCertificateVerifier(certificateVerifier);
				xadesValidator.setProcessExecutor(processExecutor);
				xadesValidator.setValidationCertPool(validationCertPool);
				xadesValidator.setSignaturePolicyProvider(signaturePolicyProvider);

				if (ASiCUtils.isOpenDocument(getMimeTypeDocument())) {
					xadesValidator.setDetachedContents(OpenDocumentSupportUtils.getOpenDocumentCoverage(extractResult));
				} else {
					xadesValidator.setDetachedContents(getSignedDocuments());
					xadesValidator.setContainerContents(getArchiveDocuments());
				}

				validators.add(xadesValidator);
			}
		}
		return validators;
	}

	@Override
	protected List<ManifestFile> getManifestFilesDecriptions() {
		List<ManifestFile> descriptions = new ArrayList<ManifestFile>();
		List<DSSDocument> signatureDocuments = getSignatureDocuments();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		// All signatures use the same file : manifest.xml
		for (DSSDocument signatureDoc : signatureDocuments) {
			for (DSSDocument manifestDoc : manifestDocuments) {
				ASiCEWithXAdESManifestParser manifestParser = new ASiCEWithXAdESManifestParser(signatureDoc, manifestDoc);
				descriptions.add(manifestParser.getDescription());
			}
		}
		return descriptions;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		List<DSSDocument> result = new ArrayList<DSSDocument>();
		List<DSSDocument> potentials = getSignedDocuments();
		for (final DSSDocument signature : getSignatureDocuments()) {
			XMLDocumentForASiCValidator xadesValidator = new XMLDocumentForASiCValidator(signature);
			xadesValidator.setCertificateVerifier(certificateVerifier);
			xadesValidator.setDetachedContents(potentials);
			List<DSSDocument> retrievedDocs = xadesValidator.getOriginalDocuments(signatureId);
			if (Utils.isCollectionNotEmpty(retrievedDocs)) {
				return extractArchiveDocuments(retrievedDocs);
			}
		}
		return result;
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		XAdESSignature xadesignature = (XAdESSignature) advancedSignature;
		List<DSSDocument> retrievedDocs = XAdESUtils.getSignerDocuments(xadesignature);
		return extractArchiveDocuments(retrievedDocs);
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
