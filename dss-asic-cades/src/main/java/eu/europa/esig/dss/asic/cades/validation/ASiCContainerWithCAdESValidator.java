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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * This class is an implementation to validate ASiC containers with CAdES signature(s)
 * 
 */
public class ASiCContainerWithCAdESValidator extends AbstractASiCContainerValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerWithCAdESValidator.class);

	ASiCContainerWithCAdESValidator() {
		super(null);
	}

	public ASiCContainerWithCAdESValidator(final DSSDocument asicContainer) {
		super(asicContainer);
		analyseEntries();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return ASiCUtils.isASiCContainer(dssDocument) && ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(dssDocument, ".p7s");
	}

	@Override
	protected AbstractASiCContainerExtractor getArchiveExtractor() {
		return new ASiCWithCAdESContainerExtractor(document);
	}

	@Override
	protected List<DocumentValidator> getValidators() {
		if (validators == null) {
			validators = new ArrayList<DocumentValidator>();
			for (final DSSDocument signature : getSignatureDocuments()) {
				CMSDocumentForASiCValidator cadesValidator = new CMSDocumentForASiCValidator(signature);
				cadesValidator.setCertificateVerifier(certificateVerifier);
				cadesValidator.setProcessExecutor(processExecutor);
				cadesValidator.setSignaturePolicyProvider(signaturePolicyProvider);
				cadesValidator.setValidationCertPool(validationCertPool);
				cadesValidator.setDetachedContents(getSignedDocuments(signature));
				cadesValidator.setContainerContents(getArchiveDocuments());
				cadesValidator.setManifestFiles(getManifestFiles());
				validators.add(cadesValidator);
			}
		}
		return validators;
	}
	
	@Override
	protected List<DSSDocument> getArchiveDocuments() {
		List<DSSDocument> archiveContents = super.getArchiveDocuments();
		// in case of Manifest file (ASiC-E CAdES signature) add signed documents
		if (Utils.isCollectionNotEmpty(getManifestDocuments())) {
			for (DSSDocument document : getSignedDocuments()) {
				if (!archiveContents.contains(document)) {
					archiveContents.add(document);
				}
			}
		}
		return archiveContents;
	}

	@Override
	protected List<TimestampToken> attachExternalTimestamps(List<AdvancedSignature> allSignatures) {
		List<TimestampToken> externalTimestamps = new ArrayList<TimestampToken>();
		
		ASiCContainerType type = getContainerType();
		if (ASiCContainerType.ASiC_E == type) {
			List<ASiCEWithCAdESTimestampValidator> currentTimestampValidators = getTimestampValidators();
			for (ASiCEWithCAdESTimestampValidator tspValidator : currentTimestampValidators) {
				TimestampToken timestamp = getExternalTimestamp(tspValidator, allSignatures);
				if (timestamp != null) {
					externalTimestamps.add(timestamp);
				}
			}
			
		}
		
		return externalTimestamps;
	}
	
	private TimestampToken getExternalTimestamp(ASiCEWithCAdESTimestampValidator tspValidator, List<AdvancedSignature> allSignatures) {
		List<ManifestEntry> coveredFiles = tspValidator.getCoveredFilenames();
		
		TimestampToken timestamp = tspValidator.getTimestamp();
		findTimestampTokenSigner(timestamp);

		if (timestamp.isSignatureValid()) {
			for (AdvancedSignature advancedSignature : allSignatures) {
				for (ManifestEntry entry : coveredFiles) {
					if (entry.getFileName() != null && entry.getFileName().contains(advancedSignature.getSignatureFilename())) {
						CAdESSignature cadesSig = (CAdESSignature) advancedSignature;
						List<TimestampToken> cadesTimestamps = new ArrayList<TimestampToken>();
						cadesTimestamps.addAll(cadesSig.getContentTimestamps());
						cadesTimestamps.addAll(cadesSig.getSignatureTimestamps());
						cadesTimestamps.addAll(cadesSig.getTimestampsX1());
						cadesTimestamps.addAll(cadesSig.getTimestampsX2());
						// Archive timestamp from CAdES is skipped

						timestamp.getTimestampedReferences().addAll(cadesSig.getTimestampReferencesForArchiveTimestamp(cadesTimestamps));
						advancedSignature.addExternalTimestamp(timestamp);
						
						return timestamp;
					}
				}
			}
		}
		
		return null;
	}
	
	private void findTimestampTokenSigner(TimestampToken timestamp) {
		// TODO temp fix
		List<CertificateToken> certificates = timestamp.getCertificates();
		for (CertificateToken candidate : certificates) {
			if (timestamp.isSignedBy(candidate)) {
				break;
			}
		}
	}

	private List<ASiCEWithCAdESTimestampValidator> getTimestampValidators() {
		List<ASiCEWithCAdESTimestampValidator> timestampValidators = new ArrayList<ASiCEWithCAdESTimestampValidator>();
		for (final DSSDocument timestamp : getTimestampDocuments()) {
			DSSDocument archiveManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getArchiveManifestDocuments(), timestamp.getName());
			if (archiveManifest != null) {
				ManifestFile manifestContent = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifest);
				ASiCEWithCAdESTimestampValidator timestampValidator = new ASiCEWithCAdESTimestampValidator(timestamp, TimestampType.ARCHIVE_TIMESTAMP,
						manifestContent.getEntries(), validationCertPool);
				timestampValidator.setCertificateVerifier(certificateVerifier);
				timestampValidator.setTimestampedData(archiveManifest);
				timestampValidators.add(timestampValidator);
			} else {
				LOG.warn("Timestamp {} is skipped (no linked archive manifest found)", timestamp.getName());
			}
		}
		return timestampValidators;
	}

	private List<DSSDocument> getSignedDocuments(DSSDocument signature) {
		ASiCContainerType type = getContainerType();
		if (ASiCContainerType.ASiC_S.equals(type)) {
			return getSignedDocuments(); // Collection size should be equals 1
		} else if (ASiCContainerType.ASiC_E.equals(type)) {
			// the manifest file is signed
			// we need first to check the manifest file and its digests
			DSSDocument linkedManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getManifestDocuments(), signature.getName());
			if (linkedManifest != null) {
				return Arrays.asList(linkedManifest);
			} else {
				return Collections.emptyList();
			}
		} else {
			LOG.warn("Unknown asic container type (returns all signed documents)");
			return getSignedDocuments();
		}
	}

	@Override
	protected List<ManifestFile> getManifestFilesDecriptions() {
		List<ManifestFile> descriptions = new ArrayList<ManifestFile>();
		List<DSSDocument> manifestDocuments = getManifestDocuments();
		for (DSSDocument manifestDocument : manifestDocuments) {
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(manifestDocument);
			ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, getSignedDocuments());
			asiceWithCAdESManifestValidator.validateEntries();
			descriptions.add(manifestFile);
		}

		List<DSSDocument> archiveManifestDocuments = getArchiveManifestDocuments();
		for (DSSDocument manifestDocument : archiveManifestDocuments) {
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(manifestDocument);
			ASiCEWithCAdESManifestValidator asiceWithCAdESManifestValidator = new ASiCEWithCAdESManifestValidator(manifestFile, getSignedDocuments());
			asiceWithCAdESManifestValidator.validateEntries();
			descriptions.add(manifestFile);
		}

		return descriptions;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		List<AdvancedSignature> signatures = getSignatures();
		for (AdvancedSignature signature : signatures) {
			if (signature.getId().equals(signatureId)) {
				return getOriginalDocuments(signature);
			}
		}
		return Collections.emptyList();
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		List<DSSDocument> retrievedDocs = advancedSignature.getDetachedContents();
		if (ASiCContainerType.ASiC_S.equals(getContainerType())) {
			return getSignedDocumentsASiCS(retrievedDocs);
		} else {
			DSSDocument linkedManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(getManifestDocuments(), advancedSignature.getSignatureFilename());
			ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(linkedManifest);
			List<ManifestEntry> entries = manifestFile.getEntries();
			List<DSSDocument> signedDocuments = getSignedDocuments();
			
			List<DSSDocument> result = new ArrayList<DSSDocument>();
			for (ManifestEntry entry : entries) {
				for (DSSDocument signedDocument : signedDocuments) {
					if (Utils.areStringsEqual(entry.getFileName(), signedDocument.getName())) {
						result.add(signedDocument);
					}
				}
			}
			return result;
		}
	}

}
