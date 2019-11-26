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
package eu.europa.esig.dss.asic.cades.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.asice.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCEWithCAdESManifestParser;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private static final String ARCHIVE_MANIFEST_FILENAME = "ASiCArchiveManifest";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_ARCHIVE_MANIFEST = ASiCUtils.META_INF_FOLDER + ARCHIVE_MANIFEST_FILENAME;
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP = ASiCUtils.META_INF_FOLDER + "timestamp001.tst";
	
	private static final String DEFAULT_ARCHIVE_MANIFEST_FILENAME = ZIP_ENTRY_ASICE_METAINF_CADES_ARCHIVE_MANIFEST + ASiCUtils.XML_EXTENSION;

	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		GetDataToSignASiCWithCAdESHelper getDataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
		return getCAdESService().getContentTimestamp(getDataToSignHelper.getToBeSigned(), parameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("List of documents to sign cannot be empty!");
		}
		GetDataToSignASiCWithCAdESHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());
		return getCAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), cadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("List of documents to sign cannot be empty!");
		}
		
		final ASiCParameters asicParameters = parameters.aSiC();
		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifests = dataToSignHelper.getManifestFiles();
		List<DSSDocument> archiveManifests = dataToSignHelper.getArchiveManifestFiles();
		List<DSSDocument> timestamps = dataToSignHelper.getTimestamps();
		
		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());

		// Archive Timestamp in case of ASiC-E is not embedded into the CAdES signature
		boolean addASiCArchiveManifest = isAddASiCEArchiveManifest(parameters);
		if (isAddASiCEArchiveManifest(parameters)) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		final DSSDocument signature = getCAdESService().signDocument(dataToSignHelper.getToBeSigned(), cadesParameters, signatureValue);
		String newSignatureFileName = dataToSignHelper.getSignatureFilename();
		signature.setName(dataToSignHelper.getSignatureFilename());

		if (ASiCUtils.isASiCS(asicParameters)) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFileName, iterator.next().getName())) {
					// remove existing file to be replaced
					iterator.remove();
				}
			}
		}
		extendedDocuments.add(signature);

		if (addASiCArchiveManifest) {
			extendWithArchiveManifest(archiveManifests, manifests, timestamps, dataToSignHelper.getSignedDocuments(), extendedDocuments, parameters);
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		List<DSSDocument> documentsToStore = new ArrayList<DSSDocument>(manifests);
		documentsToStore.addAll(archiveManifests);
		documentsToStore.addAll(timestamps);
		documentsToStore.addAll(signatures);
		excludeExtendedDocuments(documentsToStore, extendedDocuments);
		final DSSDocument asicSignature = buildASiCContainer(dataToSignHelper.getSignedDocuments(), extendedDocuments, documentsToStore, asicParameters, null);
		asicSignature
				.setName(getFinalArchiveName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), asicSignature.getMimeType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}
	
	private void excludeExtendedDocuments(List<DSSDocument> documentListToCheck, List<DSSDocument> extendedDocuments) {
		List<String> extendeDocumentNames = ASiCUtils.getDSSDocumentNames(extendedDocuments);
		Iterator<DSSDocument> iterator = documentListToCheck.iterator();
		while (iterator.hasNext()) {
			DSSDocument document = iterator.next();
			if (extendeDocumentNames.contains(document.getName())) {
				iterator.remove();
			}
		}
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
		
		if (!ASiCUtils.isZip(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(toExtendDocument, ".p7s")) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		List<DSSDocument> originalSignedDocuments = getEmbeddedSignedDocuments();
		DSSDocument mimetype = getEmbeddedMimetype();

		ASiCContainerType containerType = ASiCUtils.getContainerType(toExtendDocument, mimetype, null, originalSignedDocuments);
		if (containerType == null) {
			throw new DSSException("Unable to determine container type");
		}

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		
		boolean addASiCEArchiveManifest = isAddASiCEArchiveManifest(parameters);
		if (addASiCEArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		for (DSSDocument signature : signatureDocuments) {
			// not to extend the signature itself when extending CAdES-E LTA
			if (!addASiCEArchiveManifest || !isCoveredByArchiveManifest(signature)) {
				DSSDocument extendedSignature = extendSignatureDocument(signature, cadesParameters, containerType);
				extendedDocuments.add(extendedSignature);
			} else {
				extendedDocuments.add(signature);
			}
		}

		if (addASiCEArchiveManifest) {
			extendWithArchiveManifest(getEmbeddedArchiveManifests(), getEmbeddedManifests(), getEmbeddedTimestamps(), 
					getEmbeddedSignedDocuments(), extendedDocuments, parameters);
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments);
		extensionResult.setName(
				getFinalArchiveName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), toExtendDocument.getMimeType()));
		return extensionResult;
	}
	
	private boolean isCoveredByArchiveManifest(DSSDocument signature) {
		List<DSSDocument> archiveManifests = getEmbeddedArchiveManifests();
		if (Utils.isCollectionNotEmpty(archiveManifests)) {
			for (DSSDocument archiveManifest : archiveManifests) {
				ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifest);
				for (ManifestEntry entry : manifestFile.getEntries()) {
					if (signature.getName() != null && signature.getName().equals(entry.getFileName())) {
						return true;
					}
				}
			}
		}
		return false;
	}
	
	private DSSDocument extendSignatureDocument(DSSDocument signature, CAdESSignatureParameters cadesParameters, ASiCContainerType containerType) {

		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> originalSignedDocuments = getEmbeddedSignedDocuments();

		if (ASiCContainerType.ASiC_E == containerType) {
			DSSDocument linkedManifest = ASiCEWithCAdESManifestParser.getLinkedManifest(manifests, signature.getName());
			if (linkedManifest != null) {
				String originalName = signature.getName();
				cadesParameters.setDetachedContents(Arrays.asList(linkedManifest));

				DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
				extendDocument.setName(originalName);
				return extendDocument;
			} else {
				LOG.warn("Manifest not found for signature file '{}' -> NOT EXTENDED !!!", signature.getName());
				return signature;
			}
			
		} else {
			String originalName = signature.getName();
			cadesParameters.setDetachedContents(originalSignedDocuments);

			DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
			extendDocument.setName(originalName);
			return extendDocument;
			
		}
	}
	
	private void extendWithArchiveManifest(List<DSSDocument> archiveManifests, List<DSSDocument> manifests, List<DSSDocument> timestamps, 
			List<DSSDocument> originalSignedDocuments, List<DSSDocument> extendedDocuments, ASiCWithCAdESSignatureParameters parameters) {
		
		String timestampFilename = getArchiveTimestampFilename(timestamps);
		
		DSSDocument lastTimestamp = getLastTimestamp(timestamps);
		DSSDocument lastArchiveManifest = null;
		if (lastTimestamp != null) {
			DSSDocument extendedArchiveTimestamp = extendArchiveTimestamp(lastTimestamp, parameters.getDetachedContents());
			// a newer version of the timestamp must be created
			timestamps.remove(lastTimestamp);
			extendedDocuments.add(extendedArchiveTimestamp);
			
			for (DSSDocument manifest : archiveManifests) {
				// current ArchiveManifest must be renamed if exists
				if (DEFAULT_ARCHIVE_MANIFEST_FILENAME.equals(manifest.getName())) {
					manifest.setName(ASiCUtils.getNextASiCEManifestName(ARCHIVE_MANIFEST_FILENAME, archiveManifests));
					lastArchiveManifest = manifest;
				} else {
					// all other present manifests must be included to the computing list as well
					manifests.add(manifest);
				}
			}
		}
		
		ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(extendedDocuments, timestamps, 
				originalSignedDocuments, manifests, lastArchiveManifest, parameters.getArchiveTimestampParameters().getDigestAlgorithm(), timestampFilename);

		DSSDocument archiveManifest = DomUtils.createDssDocumentFromDomDocument(builder.build(), DEFAULT_ARCHIVE_MANIFEST_FILENAME);
		extendedDocuments.add(archiveManifest);
		if (lastArchiveManifest != null) {
			extendedDocuments.add(lastArchiveManifest);
		}

		DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManifest));
		DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timeStampResponse), timestampFilename, MimeType.TST);
		extendedDocuments.add(timestamp);

	}
	
	private DSSDocument getLastTimestamp(List<DSSDocument> timestamps) {
		DSSDocument lastTimestamp = null;
		for (DSSDocument timestamp : timestamps) {
			if (lastTimestamp == null || lastTimestamp.getName().compareTo(timestamp.getName()) < 0) {
				lastTimestamp = timestamp;
			}
		}
		return lastTimestamp;
	}
	
	private DSSDocument extendArchiveTimestamp(DSSDocument archiveTimestamp, List<DSSDocument> detachedContents) {
		CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(archiveTimestamp);
		CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		CMSSignedData extendedCMSSignedData = cmsSignedDataBuilder.extendCMSSignedData(
				cmsSignedData, cmsSignedData.getSignerInfos().iterator().next(), detachedContents);
		DSSDocument extendedTimestamp = new InMemoryDocument(DSSASN1Utils.getEncoded(extendedCMSSignedData), archiveTimestamp.getName(), MimeType.TST);
		return extendedTimestamp;
	}

	private String getArchiveTimestampFilename(List<DSSDocument> timestamps) {
		int num = Utils.collectionSize(timestamps) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
	}

	@Override
	protected boolean isSignatureFilename(String name) {
		return ASiCUtils.isCAdES(name);
	}

	@Override
	protected AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithCAdESContainerExtractor(archive);
	}

	private CAdESService getCAdESService() {
		CAdESService cadesService = new CAdESService(certificateVerifier);
		cadesService.setTspSource(tspSource);
		return cadesService;
	}

	private CAdESSignatureParameters getCAdESParameters(ASiCWithCAdESSignatureParameters parameters) {
		CAdESSignatureParameters cadesParameters = parameters;
		cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		cadesParameters.setDetachedContents(null);
		return cadesParameters;
	}

	private boolean isAddASiCEArchiveManifest(ASiCWithCAdESSignatureParameters parameters) {
		return SignatureLevel.CAdES_BASELINE_LTA == parameters.getSignatureLevel() && ASiCContainerType.ASiC_E == parameters.aSiC().getContainerType();
	}

	@Override
	protected String getExpectedSignatureExtension() {
		return ".p7s";
	}

}
