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
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampSource;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampValidatorComparator;
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
		super();
	}

	/**
	 * The default constructor
	 * 
	 * @param asicContainer {@link DSSDocument} to be validated
	 */
	public ASiCContainerWithCAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer, new ASiCWithCAdESSignatureScopeFinder());
	}

	/**
	 * The constructor with {@link ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 */
	public ASiCContainerWithCAdESValidator(final ASiCContent asicContent) {
		super(asicContent, new ASiCWithCAdESSignatureScopeFinder());
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		if (ASiCUtils.isZip(dssDocument)) {
			List<String> filenames = ZipUtils.getInstance().extractEntryNames(dssDocument);
			if (ASiCUtils.isASiCWithCAdES(filenames)) {
				return true;
			}
			// NOTE : areFilesContainMimetype check is executed in order to avoid documents reading
			return !ASiCUtils.isASiCWithXAdES(filenames) &&
					(!ASiCUtils.areFilesContainMimetype(filenames) || !ASiCUtils.isContainerOpenDocument(dssDocument));
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
				
				DSSDocument signedDocument = ASiCWithCAdESUtils.getSignedDocument(asicContent, signature.getName());
				if (signedDocument != null) {
					cadesValidator.setDetachedContents(Collections.singletonList(signedDocument));
				}
				
				DSSDocument signatureManifest = ASiCWithCAdESManifestParser.getLinkedManifest(getAllManifestDocuments(), signature.getName());
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
	 * @return a list of {@link DetachedTimestampValidator}s
	 */
	protected List<DetachedTimestampValidator> getTimestampValidators() {
		if (timestampValidators == null) {
			timestampValidators = new ArrayList<>();
			for (final DSSDocument timestamp : getTimestampDocuments()) {

				DSSDocument timestampedDocument;
				TimestampType timestampType = TimestampType.CONTENT_TIMESTAMP;
				ManifestFile manifestFile = null;

				DSSDocument archiveManifest = ASiCWithCAdESManifestParser.getLinkedManifest(
						getAllManifestDocuments(), timestamp.getName());
				if (archiveManifest != null) {
					timestampedDocument = archiveManifest;
					manifestFile = toValidatedManifestFile(archiveManifest);
					if (manifestFile != null) {
						timestampType = getTimestampType(manifestFile);
					} else {
						LOG.warn("A linked manifest is not found for a timestamp with name [{}]!",
								archiveManifest.getName());
					}

				} else {
					List<DSSDocument> rootLevelSignedDocuments = ASiCUtils.getRootLevelSignedDocuments(asicContent);
					if (Utils.collectionSize(rootLevelSignedDocuments) == 1) {
						timestampedDocument = rootLevelSignedDocuments.get(0);
					} else {
						LOG.warn("Timestamp {} is skipped (no linked archive manifest found / unique file)",
								timestamp.getName());
						continue;
					}
				}

				ASiCWithCAdESTimestampValidator timestampValidator = new ASiCWithCAdESTimestampValidator(
						timestamp, timestampType);
				timestampValidator.setTimestampedData(timestampedDocument);
				timestampValidator.setManifestFile(manifestFile);
				timestampValidator.setOriginalDocuments(getAllDocuments());
				timestampValidator.setArchiveDocuments(getArchiveDocuments());
				timestampValidator.setCertificateVerifier(certificateVerifier);

				timestampValidators.add(timestampValidator);
			}
			timestampValidators.sort(new TimestampValidatorComparator());
		}
		return timestampValidators;
	}
	
	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		DetachedTimestampSource detachedTimestampSource = new DetachedTimestampSource();
		for (DetachedTimestampValidator timestampValidator : getTimestampValidators()) {
			detachedTimestampSource.addExternalTimestamp(timestampValidator.getTimestamp());
		}
		return detachedTimestampSource.getDetachedTimestamps();
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
		
		List<DetachedTimestampValidator> currentTimestampValidators = getTimestampValidators();
		for (DetachedTimestampValidator tspValidator : currentTimestampValidators) {
			TimestampToken timestamp = getExternalTimestamp(tspValidator, allSignatures);
			if (timestamp != null) {
				externalTimestamps.add(timestamp);
			}
		}

		return externalTimestamps;
	}
	
	private TimestampToken getExternalTimestamp(TimestampValidator tspValidator, List<AdvancedSignature> allSignatures) {

		if (tspValidator instanceof ASiCWithCAdESTimestampValidator) {
			ASiCWithCAdESTimestampValidator timestampValidator = (ASiCWithCAdESTimestampValidator) tspValidator;
			TimestampToken timestamp = timestampValidator.getTimestamp();

			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getTimeStampType())) {
				ManifestFile coveredManifest = timestampValidator.getCoveredManifest();
				if (coveredManifest != null) {
					for (ManifestEntry entry : coveredManifest.getEntries()) {
						CAdESSignature cadesSignature = getCAdESSignatureFromFileName(allSignatures, entry.getFileName());
						if (cadesSignature != null) {
							cadesSignature.addExternalTimestamp(timestamp);
						}
					}
				}
			}

			return timestamp;
		}
		return null;
	}

	private CAdESSignature getCAdESSignatureFromFileName(List<AdvancedSignature> signatures, String fileName) {
		for (AdvancedSignature advancedSignature : signatures) {
			if (Utils.areStringsEqual(fileName, advancedSignature.getSignatureFilename()) &&
					!advancedSignature.isCounterSignature()) {
				return (CAdESSignature) advancedSignature;
			}
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
		return ASiCUtils.coversSignature(manifestFile) ? TimestampType.ARCHIVE_TIMESTAMP : TimestampType.CONTENT_TIMESTAMP;
	}

	@Override
	protected List<ManifestFile> getManifestFilesDescriptions() {
		List<ManifestFile> descriptions = new ArrayList<>();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		for (DSSDocument manifestDocument : manifestDocuments) {
			ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(manifestDocument);
			if (manifestFile != null) {
				ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, getAllDocuments());
				asiceWithCAdESManifestValidator.validateEntries();
				descriptions.add(manifestFile);
			}
		}

		List<DSSDocument> archiveManifestDocuments = getArchiveManifestDocuments();
		for (DSSDocument manifestDocument : archiveManifestDocuments) {
			ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(manifestDocument);
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
			DSSDocument linkedManifest = ASiCWithCAdESManifestParser.getLinkedManifest(getManifestDocuments(), advancedSignature.getSignatureFilename());
			if (linkedManifest == null) {
				return Collections.emptyList();
			}
			ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(linkedManifest);
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
