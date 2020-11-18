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
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	protected List<DocumentValidator> signatureValidators;

	protected List<DocumentValidator> timestampValidators;

	protected ASiCExtractResult extractResult;
	
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

	protected void analyseEntries() {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor();
		extractResult = extractor.extract();
	}

	protected abstract AbstractASiCContainerExtractor getArchiveExtractor();
	
	@Override
	protected DiagnosticDataBuilder createDiagnosticDataBuilder(final ValidationContext validationContext, List<AdvancedSignature> signatures,
			final ListRevocationSource<CRL> listCRLSource, final ListRevocationSource<OCSP> listOCSPSource) {
		ASiCContainerDiagnosticDataBuilder builder = (ASiCContainerDiagnosticDataBuilder) super.createDiagnosticDataBuilder(
				validationContext, signatures, listCRLSource, listOCSPSource);
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
			containerInfo.setMimeTypeFilePresent(true);
			containerInfo.setMimeTypeContent(mimeTypeContent);
		} else {
			containerInfo.setMimeTypeFilePresent(false);
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
	 * @param allSignatures list of {@link AdvancedSignature}s
	 * @return list of attached {@link TimestampToken}s
	 */
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		// Not applicable by default (used only in ASiC CAdES)
		return Collections.emptyList();
	}

	protected abstract List<ManifestFile> getManifestFilesDecriptions();

	@Override
	protected List<AdvancedSignature> getAllSignatures() {

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

	protected abstract List<DocumentValidator> getSignatureValidators();
	
	public ASiCContainerType getContainerType() {
		return extractResult.getContainerType();
	}

	public List<DSSDocument> getSignatureDocuments() {
		return extractResult.getSignatureDocuments();
	}

	public List<DSSDocument> getSignedDocuments() {
		return extractResult.getSignedDocuments();
	}

	public List<DSSDocument> getAllDocuments() {
		return extractResult.getAllDocuments();
	}

	public List<DSSDocument> getManifestDocuments() {
		return extractResult.getManifestDocuments();
	}

	public List<DSSDocument> getTimestampDocuments() {
		return extractResult.getTimestampDocuments();
	}

	public List<DSSDocument> getArchiveManifestDocuments() {
		return extractResult.getArchiveManifestDocuments();
	}
	
	public List<DSSDocument> getAllManifestDocuments() {
		return extractResult.getAllManifestDocuments();
	}
	
	public List<DSSDocument> getArchiveDocuments() {
		return extractResult.getContainerDocuments();
	}

	public DSSDocument getMimeTypeDocument() {
		return extractResult.getMimeTypeDocument();
	}
	
	public List<DSSDocument> getUnsupportedDocuments() {
		return extractResult.getUnsupportedDocuments();
	}
	
	public List<ManifestFile> getManifestFiles() {
		if (manifestFiles == null) {
			manifestFiles = getManifestFilesDecriptions();
		}
		return manifestFiles;
	}

	protected List<DSSDocument> getSignedDocumentsASiCS(List<DSSDocument> retrievedDocs) {
		if (Utils.collectionSize(retrievedDocs) > 1) {
			throw new DSSException("ASiC-S : More than one file");
		}
		List<DSSDocument> containerDocuments = extractResult.getContainerDocuments();
		if (Utils.isCollectionNotEmpty(containerDocuments)) {
			return containerDocuments;
		}
		return retrievedDocs;
	}

}
