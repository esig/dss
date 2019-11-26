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
package eu.europa.esig.dss.asic.common.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignatureValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	protected List<SignatureValidator> validators;

	protected ASiCExtractResult extractResult;

	private ASiCContainerType containerType;
	
	private List<ManifestFile> manifestFiles;

	/**
	 * Default constructor used with reflexion (see DefaultDocumentValidator)
	 */
	private AbstractASiCContainerValidator() {
		super(null);
		this.document = null;
	}

	protected AbstractASiCContainerValidator(final DSSDocument document) {
		super(null);
		this.document = document;
	}

	protected void analyseEntries() {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor();
		extractResult = extractor.extract();
		containerType = ASiCUtils.getContainerType(document, extractResult.getMimeTypeDocument(), extractResult.getZipComment(),
				extractResult.getSignedDocuments());
		if (ASiCContainerType.ASiC_S.equals(containerType)) {
			extractResult.setContainerDocuments(getArchiveDocuments(extractResult.getSignedDocuments()));
		}
	}

	protected abstract AbstractASiCContainerExtractor getArchiveExtractor();

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	@Override
	public List<AdvancedSignature> prepareSignatureValidationContext(final ValidationContext validationContext, final ValidationPolicy validationPolicy) {
		
		List<AdvancedSignature> allSignatures = new ArrayList<AdvancedSignature>();
		List<SignatureValidator> currentValidators = getValidators();
		for (SignatureValidator signatureValidator : currentValidators) { // CAdES / XAdES
			allSignatures.addAll(signatureValidator.prepareSignatureValidationContext(validationContext, validationPolicy));
		}

		// add external timestamps to the validation
		List<TimestampToken> externalTimestamps = attachExternalTimestamps(allSignatures);
		for (TimestampToken timestamp : externalTimestamps) {
			addTimestampTokenForVerification(validationContext, timestamp);
		}

		boolean structuralValidation = isRequireStructuralValidation(validationPolicy);
		return processSignaturesValidation(validationContext, allSignatures, structuralValidation);
	}
	
	private void addTimestampTokenForVerification(final ValidationContext validationContext, final TimestampToken timestamp) {
		validationContext.addTimestampTokenForVerification(timestamp);
		for (CertificateToken certificate : timestamp.getCertificates()) {
			validationContext.addCertificateTokenForVerification(certificate);
		}
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return a DTO with the container information
	 */
	@Override
	protected ContainerInfo getContainerInfo() {
		ContainerInfo containerInfo = new ContainerInfo();
		containerInfo.setContainerType(containerType);
		containerInfo.setZipComment(extractResult.getZipComment());

		DSSDocument mimeTypeDocument = extractResult.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			String mimeTypeContent = new String(DSSUtils.toByteArray(mimeTypeDocument));
			containerInfo.setMimeTypeFilePresent(true);
			containerInfo.setMimeTypeContent(mimeTypeContent);
		} else {
			containerInfo.setMimeTypeFilePresent(false);
		}

		List<DSSDocument> originalSignedDocuments = extractResult.getSignedDocuments();
		if (Utils.isCollectionNotEmpty(originalSignedDocuments)) {
			List<String> signedDocumentFilenames = new ArrayList<String>();
			for (DSSDocument dssDocument : originalSignedDocuments) {
				signedDocumentFilenames.add(dssDocument.getName());
			}
			containerInfo.setSignedDocumentFilenames(signedDocumentFilenames);
		}

		containerInfo.setManifestFiles(getManifestFiles());

		return containerInfo;
	}

	/**
	 * Attaches existing external timestamps to the list of {@code AdvancedSignature}s
	 * @param allSignatures list of {@link AdvancedSignature}s
	 * @return list of attached {@link TimestampToken}s
	 */
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		// Not applicable by default (used only in ASiC CAdES)
		return Collections.emptyList();
	}

	protected abstract List<ManifestFile> getManifestFilesDecriptions();

	@Override
	public List<AdvancedSignature> getSignatures() {
		List<AdvancedSignature> allSignatures = new ArrayList<AdvancedSignature>();
		List<SignatureValidator> currentValidators = getValidators();
		for (SignatureValidator signatureValidator : currentValidators) {
			allSignatures.addAll(signatureValidator.getSignatures());
		}

		return allSignatures;
	}

	protected abstract List<SignatureValidator> getValidators();

	protected List<DSSDocument> getSignatureDocuments() {
		return extractResult.getSignatureDocuments();
	}

	protected List<DSSDocument> getSignedDocuments() {
		return extractResult.getSignedDocuments();
	}

	protected List<DSSDocument> getAllDocuments() {
		return extractResult.getAllDocuments();
	}

	protected List<DSSDocument> getManifestDocuments() {
		return extractResult.getManifestDocuments();
	}

	protected List<DSSDocument> getTimestampDocuments() {
		return extractResult.getTimestampDocuments();
	}
	
	protected List<DSSDocument> getTimestampedDocuments(DSSDocument timestamp) {
		return extractResult.getTimestampedDocuments(timestamp);
	}

	protected List<DSSDocument> getArchiveManifestDocuments() {
		return extractResult.getArchiveManifestDocuments();
	}
	
	protected List<DSSDocument> getAllManifestDocuments() {
		return extractResult.getAllManifestDocuments();
	}
	
	protected List<DSSDocument> getArchiveDocuments() {
		return extractResult.getContainerDocuments();
	}

	protected DSSDocument getMimeTypeDocument() {
		return extractResult.getMimeTypeDocument();
	}
	
	protected List<ManifestFile> getManifestFiles() {
		if (manifestFiles == null) {
			manifestFiles = getManifestFilesDecriptions();
		}
		return manifestFiles;
	}
	
	private List<DSSDocument> getArchiveDocuments(List<DSSDocument> foundDocuments) {
		List<DSSDocument> archiveDocuments = new ArrayList<DSSDocument>();
		for (DSSDocument document : foundDocuments) {
			if (ASiCUtils.isASiCSArchive(document)) {
				archiveDocuments.addAll(ASiCUtils.getPackageZipContent(document));
				break; // only one "package.zip" is possible
			}
		}
		return archiveDocuments;
	}

	protected List<DSSDocument> getSignedDocumentsASiCS(List<DSSDocument> retrievedDocs) {
		if (Utils.collectionSize(retrievedDocs) > 1) {
			throw new DSSException("ASiC-S : More than one file");
		}
		DSSDocument uniqueDoc = retrievedDocs.get(0);
		List<DSSDocument> result = new ArrayList<DSSDocument>();
		if (ASiCUtils.isASiCSArchive(uniqueDoc)) {
			result.addAll(ASiCUtils.getPackageZipContent(uniqueDoc));
		} else {
			result.add(uniqueDoc);
		}
		return result;
	}

}
