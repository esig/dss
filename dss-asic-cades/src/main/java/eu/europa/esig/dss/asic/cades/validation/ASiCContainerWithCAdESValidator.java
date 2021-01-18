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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.validation.scope.ASiCWithCAdESSignatureScopeFinder;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is an implementation to validate ASiC containers with CAdES signature(s)
 * 
 */
public class ASiCContainerWithCAdESValidator extends AbstractASiCContainerValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerWithCAdESValidator.class);

	/**
	 * The empty constructor
	 */
	ASiCContainerWithCAdESValidator() {
		super(null);
	}

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} to be validated
	 */
	public ASiCContainerWithCAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer, new ASiCWithCAdESSignatureScopeFinder());
		extractEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		if (ASiCUtils.isZip(dssDocument)) {
			List<String> filenames = ZipUtils.getInstance().extractEntryNames(dssDocument);
			return ASiCUtils.isASiCWithCAdES(filenames);
		}
		return false;
	}

	@Override
	protected AbstractASiCContainerExtractor getContainerExtractor() {
		return new ASiCWithCAdESContainerExtractor(document);
	}
	
	@Override
	protected List<DocumentValidator> getSignatureValidators() {
		if (signatureValidators == null) {
			signatureValidators = new ArrayList<>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				CMSDocumentValidator cadesValidator = new CMSDocumentValidator(signature);
				cadesValidator.setCertificateVerifier(certificateVerifier);
				cadesValidator.setProcessExecutor(processExecutor);
				cadesValidator.setSignaturePolicyProvider(getSignaturePolicyProvider());
				cadesValidator.setContainerContents(getArchiveDocuments());
				
				DSSDocument signedDocument = ASiCWithCAdESExtractResultUtils.getSignedDocument(extractResult, signature.getName());
				if (signedDocument != null) {
					cadesValidator.setDetachedContents(Collections.singletonList(signedDocument));
				}
				
				DSSDocument signatureManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getAllManifestDocuments(), signature.getName());
				if (signatureManifest != null) {
					ManifestFile manifestFile = toValidatedManifestFile(signatureManifest);
					cadesValidator.setManifestFile(manifestFile);
				}
				
				signatureValidators.add(cadesValidator);
			}
		}
		return signatureValidators;
	}

	/**
	 * Returns a list of timestamp validators for timestamps embedded into the container
	 *
	 * @return a list of {@link DocumentValidator}s
	 */
	protected List<DocumentValidator> getTimestampValidators() {
		if (timestampValidators == null) {
			timestampValidators = new ArrayList<>();
			for (final DSSDocument timestamp : getTimestampDocuments()) {
				// timestamp's manifest can be a simple ASiCManifest as well as
				// ASiCArchiveManifest file
				DSSDocument archiveManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getAllManifestDocuments(), timestamp.getName());
				if (archiveManifest != null) {
					ManifestFile validatedManifestFile = toValidatedManifestFile(archiveManifest);
					if (validatedManifestFile != null) {
						ASiCEWithCAdESTimestampValidator timestampValidator = new ASiCEWithCAdESTimestampValidator(timestamp,
								getTimestampType(validatedManifestFile), validatedManifestFile, getAllDocuments());

						timestampValidator.setTimestampedData(archiveManifest);
						timestampValidator.setCertificateVerifier(certificateVerifier);
						timestampValidators.add(timestampValidator);
					} else {
						LOG.warn("A linked manifest is not found for a timestamp with name [{}]!", archiveManifest.getName());
					}
				} else {
					List<DSSDocument> signedDocuments = getSignedDocuments();
					if (Utils.collectionSize(signedDocuments) == 1) {
						DetachedTimestampValidator timestampValidator = new DetachedTimestampValidator(timestamp);
						timestampValidator.setTimestampedData(signedDocuments.get(0));
						timestampValidator.setCertificateVerifier(certificateVerifier);
						timestampValidators.add(timestampValidator);
					} else {
						LOG.warn("Timestamp {} is skipped (no linked archive manifest found / unique file)", timestamp.getName());
					}
				}
			}
		}
		return timestampValidators;
	}
	
	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		List<TimestampToken> independantTimestamps = new ArrayList<>();
		for (DocumentValidator timestampValidator : getTimestampValidators()) {
			independantTimestamps.addAll(timestampValidator.getDetachedTimestamps());
		}
		return independantTimestamps;
	}

	@Override
	public List<DSSDocument> getArchiveDocuments() {
		List<DSSDocument> archiveContents = super.getArchiveDocuments();
		// in case of Manifest file (ASiC-E CAdES signature) add signed documents
		if (Utils.isCollectionNotEmpty(getManifestDocuments())) {
			for (DSSDocument document : getAllDocuments()) {
				if (!archiveContents.contains(document)) {
					archiveContents.add(document);
				}
			}
		}
		return archiveContents;
	}

	@Override
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		List<TimestampToken> externalTimestamps = new ArrayList<>();
		
		List<DocumentValidator> currentTimestampValidators = getTimestampValidators();
		for (DocumentValidator tspValidator : currentTimestampValidators) {
			TimestampToken timestamp = getExternalTimestamp(tspValidator, allSignatures);
			if (timestamp != null) {
				externalTimestamps.add(timestamp);
			}
		}

		return externalTimestamps;
	}
	
	private TimestampToken getExternalTimestamp(DocumentValidator tspValidator, List<AdvancedSignature> allSignatures) {

		if (tspValidator instanceof ASiCEWithCAdESTimestampValidator) {

			ASiCEWithCAdESTimestampValidator manifestBasedTimestampValidator = (ASiCEWithCAdESTimestampValidator) tspValidator;

			TimestampToken timestamp = manifestBasedTimestampValidator.getTimestamp();

			ManifestFile coveredManifest = manifestBasedTimestampValidator.getCoveredManifest();
			for (ManifestEntry entry : coveredManifest.getEntries()) {
				for (AdvancedSignature advancedSignature : allSignatures) {
					if (Utils.areStringsEqual(entry.getFileName(), advancedSignature.getSignatureFilename()) &&
							!advancedSignature.isCounterSignature()) {
						CAdESSignature cadesSig = (CAdESSignature) advancedSignature;
						timestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_DETACHED);
						
						cadesSig.addExternalTimestamp(timestamp);
					}
				}
			}
			return timestamp;
		} else if (tspValidator instanceof DetachedTimestampValidator) {
			return ((DetachedTimestampValidator) tspValidator).getTimestamp();
		}
		
		return null;
	}
	
	private ManifestFile toValidatedManifestFile(DSSDocument manifest) {
		List<ManifestFile> manifestFiles = getManifestFiles();
		if (Utils.isCollectionNotEmpty(manifestFiles)) {
			for (ManifestFile manifestFile : manifestFiles) {
				if (Utils.areStringsEqual(manifest.getName(), manifestFile.getFilename())) {
					return manifestFile;
				}
			}
		}
		return null;
	}
	
	private TimestampType getTimestampType(ManifestFile manifestFile) {
		return coversSignature(manifestFile) ? TimestampType.ARCHIVE_TIMESTAMP : TimestampType.CONTENT_TIMESTAMP;
	}

	/**
	 * Checks if the manifestFile covers a signature
	 * @return TRUE if manifest entries contain a signature, FALSE otherwise
	 */
	private boolean coversSignature(ManifestFile manifestFile) {
		for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
			if (ASiCUtils.isSignature(manifestEntry.getFileName())) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected List<ManifestFile> getManifestFilesDescriptions() {
		List<ManifestFile> descriptions = new ArrayList<>();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		for (DSSDocument manifestDocument : manifestDocuments) {
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(manifestDocument);
			if (manifestFile != null) {
				ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, getAllDocuments());
				asiceWithCAdESManifestValidator.validateEntries();
				descriptions.add(manifestFile);
			}
		}

		List<DSSDocument> archiveManifestDocuments = getArchiveManifestDocuments();
		for (DSSDocument manifestDocument : archiveManifestDocuments) {
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(manifestDocument);
			if (manifestFile != null) {
				manifestFile.setArchiveManifest(true);
				ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, getAllDocuments());
				asiceWithCAdESManifestValidator.validateEntries();
				descriptions.add(manifestFile);
			}
		}

		return descriptions;
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		if (advancedSignature.isCounterSignature()) {
			CAdESSignature cadesSignature = (CAdESSignature) advancedSignature;
			return Arrays.asList(cadesSignature.getOriginalDocument());
		}
		List<DSSDocument> retrievedDocs = advancedSignature.getDetachedContents();
		if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
			return getSignedDocumentsASiCS(retrievedDocs);
		} else {
			DSSDocument linkedManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getManifestDocuments(), advancedSignature.getSignatureFilename());
			if (linkedManifest == null) {
				return Collections.emptyList();
			}
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(linkedManifest);
			return getManifestedDocuments(manifestFile);
		}
	}
	
	private List<DSSDocument> getManifestedDocuments(ManifestFile manifestFile) {
		List<ManifestEntry> entries = manifestFile.getEntries();
		List<DSSDocument> signedDocuments = getAllDocuments();
		
		List<DSSDocument> result = new ArrayList<>();
		for (ManifestEntry entry : entries) {
			for (DSSDocument signedDocument : signedDocuments) {
				if (Utils.areStringsEqual(entry.getFileName(), signedDocument.getName())) {
					result.add(signedDocument);
				}
			}
		}
		return result;
	}

	@Override
	protected ASiCWithCAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new ASiCWithCAdESDiagnosticDataBuilder();
	}

}
