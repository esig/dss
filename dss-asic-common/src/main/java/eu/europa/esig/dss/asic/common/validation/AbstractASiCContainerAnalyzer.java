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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.ContainerInfo;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.validation.analyzer.timestamp.TimestampAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The abstract class for an ASiC container validation
 */
public abstract class AbstractASiCContainerAnalyzer extends DefaultDocumentAnalyzer {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerAnalyzer.class);

	/** The container extraction result */
	protected ASiCContent asicContent;

	/** List of signature document analyzers */
	protected List<eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer> signatureValidators;

	/** List of timestamp document validators */
	protected List<TimestampAnalyzer> timestampAnalyzers;

	/** List of evidence record document validators */
	protected List<EvidenceRecordAnalyzer> evidenceRecordAnalyzers;

	/** List of manifest files */
	private List<ManifestFile> manifestFiles;

	/**
	 * Empty constructor
	 */
	protected AbstractASiCContainerAnalyzer() {
		super();
	}

	/**
	 * The default constructor
	 * 
	 * @param document {@link DSSDocument} to be validated
	 */
	protected AbstractASiCContainerAnalyzer(final DSSDocument document) {
		this.document = document;
		this.asicContent = extractEntries();
	}

	/**
	 * The constructor with {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 */
	protected AbstractASiCContainerAnalyzer(final ASiCContent asicContent) {
		this.document = asicContent.getAsicContainer();
		this.asicContent = asicContent;
	}

	/**
	 * Checks if the {@code ASiCContent} is supported by the current validator
	 *
	 * @param asicContent {@link ASiCContent} to check
	 * @return TRUE if the ASiC Content is supported, FALSE otherwise
	 */
	public abstract boolean isSupported(ASiCContent asicContent);

	/**
	 * Extracts documents from a container
	 */
	private ASiCContent extractEntries() {
		DefaultASiCContainerExtractor extractor = getContainerExtractor();
		return extractor.extract();
	}

	/**
	 * Returns the relevant container extractor
	 *
	 * @return {@link DefaultASiCContainerExtractor}
	 */
	protected abstract DefaultASiCContainerExtractor getContainerExtractor();

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return a DTO with the container information
	 */
	protected ContainerInfo getContainerInfo() {
		ContainerInfo containerInfo = new ContainerInfo();
		containerInfo.setContainerType(asicContent.getContainerType());
		containerInfo.setZipComment(asicContent.getZipComment());

		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			String mimeTypeContent = new String(DSSUtils.toByteArray(mimeTypeDocument));
			containerInfo.setMimeTypeContent(mimeTypeContent);
		}

		List<DSSDocument> originalSignedDocuments = asicContent.getSignedDocuments();
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
		final List<AdvancedSignature> allSignatureList = super.getAllSignatures();
		attachExternalTimestamps(allSignatureList);
		return allSignatureList;
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		final List<AdvancedSignature> signatureList = new ArrayList<>();
		for (eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer validator : getSignatureAnalyzers()) {
			signatureList.addAll(validator.getSignatures());
		}
		
		return signatureList;
	}

	/**
	 * Returns a list of validators for signature documents embedded into the container
	 *
	 * @return a list of {@link DocumentValidator}s
	 */
	protected abstract List<eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer> getSignatureAnalyzers();

	/**
	 * Returns a container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return asicContent.getContainerType();
	}

	/**
	 * Returns a list of all embedded  documents
	 *
	 * @return a list of all embedded {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		return asicContent.getAllDocuments();
	}

	/**
	 * Returns a list of embedded signature documents
	 *
	 * @return a list of signature {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		return asicContent.getSignatureDocuments();
	}

	/**
	 * Returns a list of embedded signed documents
	 *
	 * @return a list of signed {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocuments() {
		return asicContent.getSignedDocuments();
	}

	/**
	 * Returns a list of embedded signature manifest documents
	 *
	 * @return a list of signature manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getManifestDocuments() {
		return asicContent.getManifestDocuments();
	}

	/**
	 * Returns a list of embedded timestamp documents
	 *
	 * @return a list of timestamp {@link DSSDocument}s
	 */
	public List<DSSDocument> getTimestampDocuments() {
		return asicContent.getTimestampDocuments();
	}

	/**
	 * Returns a list of embedded evidence record documents
	 *
	 * @return a list of evidence record {@link DSSDocument}s
	 */
	public List<DSSDocument> getEvidenceRecordDocuments() {
		return asicContent.getEvidenceRecordDocuments();
	}

	/**
	 * Returns a list of embedded archive manifest documents
	 *
	 * @return a list of archive manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveManifestDocuments() {
		return asicContent.getArchiveManifestDocuments();
	}

	/**
	 * Returns a list of embedded evidence record manifest documents
	 *
	 * @return a list of evidence record manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getEvidenceRecordManifestDocuments() {
		return asicContent.getEvidenceRecordManifestDocuments();
	}

	/**
	 * Returns a list of all embedded manifest documents
	 *
	 * @return a list of manifest {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		return asicContent.getAllManifestDocuments();
	}

	/**
	 * Returns a list of archive documents embedded the container
	 *
	 * @return a list of archive {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveDocuments() {
		return asicContent.getContainerDocuments();
	}

	/**
	 * Returns a mimetype document
	 *
	 * @return {@link DSSDocument} mimetype
	 */
	public DSSDocument getMimeTypeDocument() {
		return asicContent.getMimeTypeDocument();
	}

	/**
	 * Returns a list of unsupported documents from the container
	 *
	 * @return a list of unsupported documents {@link DSSDocument}s
	 */
	public List<DSSDocument> getUnsupportedDocuments() {
		return asicContent.getUnsupportedDocuments();
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
		List<DSSDocument> containerDocuments = asicContent.getContainerDocuments();
		if (Utils.isCollectionNotEmpty(containerDocuments)) {
			return containerDocuments;
		}
		return retrievedDocs;
	}

	@Override
	protected List<EvidenceRecord> buildDetachedEvidenceRecords() {
		final List<EvidenceRecord> embeddedEvidenceRecords = new ArrayList<>();
		for (EvidenceRecordAnalyzer evidenceRecordAnalyzer : getEvidenceRecordAnalyzers()) {
			EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordAnalyzer);
			if (evidenceRecord != null) {
				embeddedEvidenceRecords.add(evidenceRecord);
			}
		}
		final List<EvidenceRecord> detachedEvidenceRecords = new ArrayList<>(super.buildDetachedEvidenceRecords());
		attachExternalEvidenceRecords(embeddedEvidenceRecords, detachedEvidenceRecords);
		// return all
		detachedEvidenceRecords.addAll(embeddedEvidenceRecords);
		return detachedEvidenceRecords;
	}

	/**
	 * Appends detached evidence record provided to the validator to
	 * the evidence records covered by the corresponding evidence records
	 *
	 * @param embeddedEvidenceRecords a list of {@link EvidenceRecord}s extracted from the ASiC container
	 * @param detachedEvidenceRecords a list of {@link EvidenceRecord}s provided externally to the validation
	 */
	protected void attachExternalEvidenceRecords(List<EvidenceRecord> embeddedEvidenceRecords, List<EvidenceRecord> detachedEvidenceRecords) {
		if (Utils.isCollectionNotEmpty(embeddedEvidenceRecords)) {
			for (EvidenceRecord coveredEvidenceRecord : embeddedEvidenceRecords) {
				for (EvidenceRecord coveringEvidenceRecord : embeddedEvidenceRecords) {
					if (coversEvidenceRecord(coveredEvidenceRecord, coveringEvidenceRecord)) {
						coveredEvidenceRecord.addExternalEvidenceRecord(coveringEvidenceRecord);
					}
				}
				// assert all detached evidence records cover embedded data
				for (EvidenceRecord coveringEvidenceRecord : detachedEvidenceRecords) {
					coveredEvidenceRecord.addExternalEvidenceRecord(coveringEvidenceRecord);
				}
			}
		}
	}

	/**
	 * Builds and returns a list of evidence record analyzers
	 *
	 * @return a list of {@link EvidenceRecordAnalyzer}
	 */
	protected List<EvidenceRecordAnalyzer> getEvidenceRecordAnalyzers() {
		if (evidenceRecordAnalyzers == null) {
			evidenceRecordAnalyzers = new ArrayList<>();
			for (final DSSDocument evidenceRecordDocument : getEvidenceRecordDocuments()) {
				EvidenceRecordAnalyzer evidenceRecordAnalyzer = getEvidenceRecordAnalyzer(evidenceRecordDocument);
				if (evidenceRecordAnalyzer != null) {
					evidenceRecordAnalyzers.add(evidenceRecordAnalyzer);
				}
			}
		}
		return evidenceRecordAnalyzers;
	}

	private EvidenceRecordAnalyzer getEvidenceRecordAnalyzer(DSSDocument evidenceRecordDocument) {
		try {
			ManifestFile manifestFile = null;
			List<DSSDocument> detachedContents = getAllDocuments();

			DSSDocument evidenceRecordManifest = ASiCManifestParser.getLinkedManifest(
					getEvidenceRecordManifestDocuments(), evidenceRecordDocument.getName());
			if (evidenceRecordManifest != null) {
				manifestFile = getValidatedManifestFile(evidenceRecordManifest);
			}

			if (ASiCUtils.isASiCSContainer(asicContent)) {
				if (manifestFile != null) {
					LOG.warn("A linked ASiCEvidenceRecordManifest '{}' was found for an evidence record with name '{}'. " +
									"The manifest processing is ignored, as not required for ASiC-S format.",
							manifestFile.getFilename(), evidenceRecordDocument.getName());
					manifestFile = null;
				}
				List<DSSDocument> rootLevelSignedDocuments = ASiCUtils.getRootLevelSignedDocuments(asicContent);
				if (Utils.collectionSize(rootLevelSignedDocuments) == 1) {
					detachedContents = rootLevelSignedDocuments;
				} else {
					LOG.warn("'{}' documents found at the root level. Not applicable for an ASiC-S container!",
							Utils.collectionSize(rootLevelSignedDocuments));
					detachedContents = Collections.emptyList();
				}

			} else {
				if (manifestFile == null) {
					LOG.warn("A linked ASiCEvidenceRecordManifest is required for ASiC-E container " +
									"but was not found for an evidence record with name '{}'!",
							evidenceRecordDocument.getName());
					detachedContents = Collections.emptyList();
					manifestFile = new ManifestFile(); // empty manifest
				}
			}

			final EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);
			assertEvidenceRecordDocumentExtensionMatch(evidenceRecordDocument, evidenceRecordAnalyzer.getEvidenceRecordType());
			evidenceRecordAnalyzer.setDetachedContents(detachedContents);
			evidenceRecordAnalyzer.setManifestFile(manifestFile);
			evidenceRecordAnalyzer.setCertificateVerifier(certificateVerifier);
			evidenceRecordAnalyzer.setEvidenceRecordOrigin(EvidenceRecordOrigin.CONTAINER);
			return evidenceRecordAnalyzer;

		} catch (Exception e) {
			LOG.warn("Unable to load EvidenceRecordValidator for an evidence record document with name '{}' : {}",
					evidenceRecordDocument.getName(), e.getMessage(), e);
			return null;
		}
	}

	/**
	 * This method verifies whether the extension of {@code evidenceRecordDocument} is conformant to
	 * the applicable standard for the given {@code evidenceRecordTypeEnum}
	 *
	 * @param evidenceRecordDocument {@link DSSDocument} to be validated
	 * @param evidenceRecordTypeEnum {@link EvidenceRecordTypeEnum} identified for the document
	 */
	protected void assertEvidenceRecordDocumentExtensionMatch(DSSDocument evidenceRecordDocument, EvidenceRecordTypeEnum evidenceRecordTypeEnum) {
		switch (evidenceRecordTypeEnum) {
			case XML_EVIDENCE_RECORD:
				if (evidenceRecordDocument.getName() != null && !evidenceRecordDocument.getName().endsWith(ASiCUtils.XML_EXTENSION)) {
					throw new DSSException("Document containing an XMLERS evidence record shall end with '.xml' extension!");
				}
				break;
			case ASN1_EVIDENCE_RECORD:
				if (evidenceRecordDocument.getName() != null && !evidenceRecordDocument.getName().endsWith(ASiCUtils.ER_ASN1_EXTENSION)) {
					throw new DSSException("Document containing an ERS evidence record shall end with '.ers' extension!");
				}
				break;
			default:
				throw new UnsupportedOperationException(String.format("The evidence record type '%s' is not supported!", evidenceRecordTypeEnum));
		}
	}

	@Override
	protected boolean coversSignature(AdvancedSignature signature, EvidenceRecord evidenceRecord) {
		ManifestFile evidenceRecordManifest = evidenceRecord.getManifestFile();
		if (evidenceRecordManifest == null) {
			// not embedded ER
			return true;
		}
		return coversFile(evidenceRecordManifest, signature.getFilename());
	}

	private boolean coversEvidenceRecord(EvidenceRecord coveredEvidenceRecord, EvidenceRecord coveringEvidenceRecord) {
		ManifestFile evidenceRecordManifest = coveringEvidenceRecord.getManifestFile();
		if (evidenceRecordManifest == null) {
			return false;
		}
		return coversFile(evidenceRecordManifest, coveredEvidenceRecord.getFilename());
	}

	private boolean coversFile(ManifestFile manifestFile, String filename) {
		if (manifestFile != null) {
			for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
				if (Utils.areStringsEqual(filename, manifestEntry.getUri())) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns a validated {@code ManifestFile} for the given {@code manifest} document
	 *
	 * @param manifest {@link DSSDocument}
	 * @return {@link ManifestFile}
	 */
	protected ManifestFile getValidatedManifestFile(DSSDocument manifest) {
		List<ManifestFile> allManifestFiles = getManifestFiles();
		if (Utils.isCollectionNotEmpty(allManifestFiles)) {
			for (ManifestFile manifestFile : allManifestFiles) {
				if (Utils.areStringsEqual(manifest.getName(), manifestFile.getFilename())) {
					return manifestFile;
				}
			}
		}
		return null;
	}

	@Override
	protected boolean addReference(SignatureScope signatureScope) {
		String fileName = signatureScope.getDocumentName();
		return fileName == null || (!ASiCUtils.isSignature(fileName) && !ASiCUtils.isTimestamp(fileName) && !ASiCUtils.isEvidenceRecord(fileName));
	}

}
