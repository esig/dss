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

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The abstract class for an ASiC container validation
 */
public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	/** List of signature document validators */
	protected List<DocumentValidator> signatureValidators;

	/** List of timestamp document validators */
	protected List<DetachedTimestampValidator> timestampValidators;

	/** The container extraction result */
	protected ASiCExtractResult extractResult;

	/** List of manifest files */
	private List<ManifestFile> manifestFiles;

	/**
	 * The default constructor
	 * 
	 * @param document {@link DSSDocument} to be validated
	 */
	protected AbstractASiCContainerValidator(final DSSDocument document) {
		this(document, null);
	}

	/**
	 * Constructor with a custom {@code SignatureScopeFinder}
	 * 
	 * @param document             {@link DSSDocument} to be validated
	 * @param signatureScopeFinder {@link SignatureScopeFinder} to be used
	 */
	protected AbstractASiCContainerValidator(final DSSDocument document,
			final SignatureScopeFinder signatureScopeFinder) {
		super(signatureScopeFinder);
		this.document = document;
	}

	/**
	 * Extracts documents from a container
	 */
	protected void extractEntries() {
		AbstractASiCContainerExtractor extractor = getContainerExtractor();
		extractResult = extractor.extract();
	}

	/**
	 * Returns the relevant container extractor
	 *
	 * @return {@link AbstractASiCContainerExtractor}
	 */
	protected abstract AbstractASiCContainerExtractor getContainerExtractor();
	
	@Override
	protected DiagnosticDataBuilder createDiagnosticDataBuilder(final ValidationContext validationContext,
																final List<AdvancedSignature> signatures) {
		ASiCContainerDiagnosticDataBuilder builder = (ASiCContainerDiagnosticDataBuilder) super.createDiagnosticDataBuilder(
				validationContext, signatures);
		builder.containerInfo(getContainerInfo());
		return builder;
	}

	@Override
	protected ASiCContainerDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new ASiCContainerDiagnosticDataBuilder();
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return a DTO with the container information
	 */
	protected ContainerInfo getContainerInfo() {
		ContainerInfo containerInfo = new ContainerInfo();
		containerInfo.setContainerType(extractResult.getContainerType());
		containerInfo.setZipComment(extractResult.getZipComment());

		DSSDocument mimeTypeDocument = extractResult.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			String mimeTypeContent = new String(DSSUtils.toByteArray(mimeTypeDocument));
			containerInfo.setMimeTypeContent(mimeTypeContent);
		}

		List<DSSDocument> originalSignedDocuments = extractResult.getSignedDocuments();
		if (Utils.isCollectionNotEmpty(originalSignedDocuments)) {
			List<String> signedDocumentFilenames = new ArrayList<>();
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
	 *
	 * @param allSignatures list of {@link AdvancedSignature}s
	 * @return list of attached {@link TimestampToken}s
	 */
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		// Not applicable by default (used only in ASiC CAdES)
		return Collections.emptyList();
	}

	/**
	 * Returns a list of parser ManifestFiles
	 *
	 * @return a list of {@link ManifestFile}s
	 */
	protected abstract List<ManifestFile> getManifestFilesDescriptions();

	@Override
	public List<AdvancedSignature> getAllSignatures() {

		setSignedScopeFinderDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());

		final List<AdvancedSignature> allSignatureList = new ArrayList<>();

		List<DocumentValidator> currentValidators = getSignatureValidators();
		for (DocumentValidator signatureValidator : currentValidators) {

			List<AdvancedSignature> signatures = signatureValidator.getSignatures();
			for (AdvancedSignature advancedSignature : signatures) {
				allSignatureList.add(advancedSignature);
				appendCounterSignatures(allSignatureList, advancedSignature);
			}

		}

		findSignatureScopes(allSignatureList);
		attachExternalTimestamps(allSignatureList);

		return allSignatureList;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		final List<AdvancedSignature> signatureList = new ArrayList<>();
		for (DocumentValidator validator : getSignatureValidators()) {
			for (final AdvancedSignature advancedSignature : validator.getSignatures()) {
				signatureList.add(advancedSignature);
			}
		}
		
		return signatureList;
	}

	/**
	 * Returns a list of validators for signature documents embedded into the container
	 *
	 * @return a list of {@link DocumentValidator}s
	 */
	protected abstract List<DocumentValidator> getSignatureValidators();

	/**
	 * Returns a container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return extractResult.getContainerType();
	}

	/**
	 * Returns a list of all embedded  documents
	 *
	 * @return a list of all embedded {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		return extractResult.getAllDocuments();
	}

	/**
	 * Returns a list of embedded signature documents
	 *
	 * @return a list of signature {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		return extractResult.getSignatureDocuments();
	}

	/**
	 * Returns a list of embedded signed documents
	 *
	 * @return a list of signed {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocuments() {
		return extractResult.getSignedDocuments();
	}

	/**
	 * Returns a list of embedded signature manifest documents
	 *
	 * @return a list of signature manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getManifestDocuments() {
		return extractResult.getManifestDocuments();
	}

	/**
	 * Returns a list of embedded timestamp documents
	 *
	 * @return a list of timestamp {@link DSSDocument}s
	 */
	public List<DSSDocument> getTimestampDocuments() {
		return extractResult.getTimestampDocuments();
	}

	/**
	 * Returns a list of embedded archive manifest documents
	 *
	 * @return a list of archive manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveManifestDocuments() {
		return extractResult.getArchiveManifestDocuments();
	}

	/**
	 * Returns a list of all embedded manifest documents
	 *
	 * @return a list of manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		return extractResult.getAllManifestDocuments();
	}

	/**
	 * Returns a list of archive documents embedded the container
	 *
	 * @return a list of archive {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveDocuments() {
		return extractResult.getContainerDocuments();
	}

	/**
	 * Returns a mimetype document
	 *
	 * @return {@link DSSDocument} mimetype
	 */
	public DSSDocument getMimeTypeDocument() {
		return extractResult.getMimeTypeDocument();
	}

	/**
	 * Returns a list of unsupported documents from the container
	 *
	 * @return a list of unsupported documents {@link DSSDocument}s
	 */
	public List<DSSDocument> getUnsupportedDocuments() {
		return extractResult.getUnsupportedDocuments();
	}

	/**
	 * Returns a list of parser Manifest files
	 *
	 * @return a list of {@link ManifestFile}s
	 */
	public List<ManifestFile> getManifestFiles() {
		if (manifestFiles == null) {
			manifestFiles = getManifestFilesDescriptions();
		}
		return manifestFiles;
	}

	/**
	 * Returns a list of "package.zip" documents
	 *
	 * @param retrievedDocs the retrieved signed documents
	 * @return a list of {@link DSSDocument}s
	 */
	protected List<DSSDocument> getSignedDocumentsASiCS(List<DSSDocument> retrievedDocs) {
		List<DSSDocument> containerDocuments = extractResult.getContainerDocuments();
		if (Utils.isCollectionNotEmpty(containerDocuments)) {
			return containerDocuments;
		}
		return retrievedDocs;
	}

}
