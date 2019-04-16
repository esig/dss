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
package eu.europa.esig.dss.asic.validation;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;

public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

	protected List<DocumentValidator> validators;

	protected ASiCExtractResult extractResult;

	private ASiCContainerType containerType;

	/**
	 * Default constructor used with reflexion (see SignedDocumentValidator)
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
		} else if (ASiCContainerType.ASiC_E.equals(containerType)) {
			extractResult.setManifestFiles(getManifestFilesDecriptions());
		}
	}

	abstract AbstractASiCContainerExtractor getArchiveExtractor();

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	@Override
	public List<AdvancedSignature> processSignaturesValidation(final ValidationContext validationContext, boolean structuralValidation) {
		List<AdvancedSignature> allSignatures = new ArrayList<AdvancedSignature>();
		List<DocumentValidator> currentValidators = getValidators();
		for (DocumentValidator documentValidator : currentValidators) { // CAdES / XAdES
			allSignatures.addAll(documentValidator.processSignaturesValidation(validationContext, structuralValidation));
		}

		// for CAdES
		attachExternalTimestamps(allSignatures);

		return allSignatures;
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

		List<DSSDocument> signedDocuments = extractResult.getSignedDocuments();
		if (Utils.isCollectionNotEmpty(signedDocuments)) {
			List<String> signedDocumentFilenames = new ArrayList<String>();
			for (DSSDocument dssDocument : signedDocuments) {
				signedDocumentFilenames.add(dssDocument.getName());
			}
			containerInfo.setSignedDocumentFilenames(signedDocumentFilenames);
		}

		containerInfo.setManifestFiles(getManifestFiles());

		return containerInfo;
	}

	protected abstract void attachExternalTimestamps(List<AdvancedSignature> allSignatures);

	protected abstract List<ManifestFile> getManifestFilesDecriptions();

	@Override
	public List<AdvancedSignature> getSignatures() {
		List<AdvancedSignature> allSignatures = new ArrayList<AdvancedSignature>();
		List<DocumentValidator> currentValidators = getValidators();
		for (DocumentValidator documentValidator : currentValidators) {
			allSignatures.addAll(documentValidator.getSignatures());
		}

		return allSignatures;
	}

	abstract List<DocumentValidator> getValidators();

	protected List<DSSDocument> getSignatureDocuments() {
		return extractResult.getSignatureDocuments();
	}

	protected List<DSSDocument> getSignedDocuments() {
		return extractResult.getSignedDocuments();
	}

	protected List<DSSDocument> getManifestDocuments() {
		return extractResult.getManifestDocuments();
	}
	
	protected List<ManifestFile> getManifestFiles() {
		return extractResult.getManifestFiles();
	}

	protected List<DSSDocument> getTimestampDocuments() {
		return extractResult.getTimestampDocuments();
	}

	protected List<DSSDocument> getArchiveManifestDocuments() {
		return extractResult.getArchiveManifestDocuments();
	}
	
	protected List<DSSDocument> getArchiveDocuments() {
		return extractResult.getContainerDocuments();
	}

	protected DSSDocument getMimeTypeDocument() {
		return extractResult.getMimeTypeDocument();
	}
	
	private List<DSSDocument> getArchiveDocuments(List<DSSDocument> foundDocuments) {
		List<DSSDocument> archiveDocuments = new ArrayList<DSSDocument>();
		for (DSSDocument document : foundDocuments) {
			if (isASiCSArchive(document)) {
				archiveDocuments.addAll(getPackageZipContent(document));
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
		if (isASiCSArchive(uniqueDoc)) {
			result.addAll(getPackageZipContent(uniqueDoc));
		} else {
			result.add(uniqueDoc);
		}
		return result;
	}
	
	private boolean isASiCSArchive(DSSDocument document) {
		return Utils.areStringsEqual(ASiCUtils.PACKAGE_ZIP, document.getName());
	}

	private List<DSSDocument> getPackageZipContent(DSSDocument packageZip) {
		List<DSSDocument> result = new ArrayList<DSSDocument>();
		try (InputStream is = packageZip.openStream(); ZipInputStream packageZipInputStream = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = packageZipInputStream.getNextEntry()) != null) {
				result.add(ASiCUtils.getCurrentDocument(entry.getName(), packageZipInputStream));
			}
		} catch (IOException e) {
			throw new DSSException("Unable to extract package.zip", e);
		}
		return result;
	}

}
