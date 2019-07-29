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

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.asice.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCEWithCAdESManifestValidator;
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
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private static final String ARCHIVE_MANIFEST_EXTENSION = ".xml";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_ARCHIVE_MANIFEST = "META-INF/ASiCArchiveManifest";
	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP = "META-INF/timestamp001.tst";
	
	private static final String DEFAULT_ARCHIVE_MANIFEST_FILENAME = ZIP_ENTRY_ASICE_METAINF_CADES_ARCHIVE_MANIFEST + ARCHIVE_MANIFEST_EXTENSION;

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
		GetDataToSignASiCWithCAdESHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());
		return getCAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), cadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters, SignatureValue signatureValue) {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifests = dataToSignHelper.getManifestFiles();
		List<DSSDocument> archiveManifests = getEmbeddedArchiveManifests();
		List<DSSDocument> timestamps = getEmbeddedTimestamps();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());

		// Archive Timestamp in case of ASiC-E is not embedded in the CAdES signature
		boolean addASiCArchiveManifest = false;
		if (isAddASiCArchiveManifest(parameters)) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
			addASiCArchiveManifest = true;
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
		signatures.add(signature);

		if (addASiCArchiveManifest) {
			String timestampFilename = getArchiveTimestampFilename(timestamps);
			ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(signatures, timestamps, dataToSignHelper.getSignedDocuments(),
					manifests, parameters.getArchiveTimestampParameters().getDigestAlgorithm(), timestampFilename);

			DSSDocument archiveManfest = DomUtils.createDssDocumentFromDomDocument(builder.build(), getArchiveManifestFilename(archiveManifests));
			signatures.add(archiveManfest);

			DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
			TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManfest));
			DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timeStampResponse), timestampFilename, MimeType.TST);
			signatures.add(timestamp);

			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		final DSSDocument asicSignature = buildASiCContainer(dataToSignHelper.getSignedDocuments(), signatures, manifests, asicParameters);
		asicSignature
				.setName(getFinalFileName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) {
		if (!ASiCUtils.isASiCContainer(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(toExtendDocument, ".p7s")) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();
		DSSDocument mimetype = getEmbeddedMimetype();

		ASiCContainerType containerType = ASiCUtils.getContainerType(toExtendDocument, mimetype, null, signedDocuments);
		if (containerType == null) {
			throw new DSSException("Unable to determine container type");
		}

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		
		boolean addASiCArchiveManifest = isAddASiCArchiveManifest(parameters);
		if (addASiCArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		for (DSSDocument signature : signatureDocuments) {
			DSSDocument extendedSignature = extendSignatureDocument(signature, cadesParameters, containerType);
			extendedDocuments.add(extendedSignature);
		}

		if (addASiCArchiveManifest) {
			extendWithArchiveManifest(parameters, extendedDocuments);
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments);
		extensionResult.setName(
				getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		return extensionResult;
	}
	
	private DSSDocument extendSignatureDocument(DSSDocument signature, CAdESSignatureParameters cadesParameters, ASiCContainerType containerType) {

		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();

		if (ASiCContainerType.ASiC_E == containerType) {
			ASiCEWithCAdESManifestValidator manifestValidator = new ASiCEWithCAdESManifestValidator(signature, manifests, signedDocuments);
			
			DSSDocument linkedManifest = manifestValidator.getLinkedManifest();
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
			cadesParameters.setDetachedContents(signedDocuments);

			DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
			extendDocument.setName(originalName);
			return extendDocument;
			
		}
	}
	
	private void extendWithArchiveManifest(ASiCWithCAdESSignatureParameters parameters, List<DSSDocument> extendedDocuments) {
		
		List<DSSDocument> archiveManifests = getEmbeddedArchiveManifests();
		List<DSSDocument> timestamps = getEmbeddedTimestamps();
		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();
		
		String timestampFilename = getArchiveTimestampFilename(timestamps);
		
		DSSDocument lastTimestamp = getLastTimestamp(timestamps);
		if (lastTimestamp != null) {
			DSSDocument extendedArchiveTimestamp = extendArchiveTimestamp(lastTimestamp, parameters.getDetachedContents());
			// a newer version of the timestamp must be created
			timestamps.remove(lastTimestamp);
			extendedDocuments.add(extendedArchiveTimestamp);
			
			for (DSSDocument manifest : archiveManifests) {
				// current ArchiveManifest must be renamed if exists
				if (DEFAULT_ARCHIVE_MANIFEST_FILENAME.equals(manifest.getName())) {
					manifest.setName(getArchiveManifestFilename(archiveManifests));
					extendedDocuments.add(manifest);
				} else {
					// all other present manifests must be included to the computing list as well
					manifests.add(manifest);
				}
			}
		}
		
		ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(extendedDocuments, timestamps, 
				signedDocuments, manifests, parameters.getArchiveTimestampParameters().getDigestAlgorithm(), timestampFilename);

		DSSDocument archiveManfest = DomUtils.createDssDocumentFromDomDocument(builder.build(), DEFAULT_ARCHIVE_MANIFEST_FILENAME);
		extendedDocuments.add(archiveManfest);

		DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManfest));
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

	private String getArchiveManifestFilename(List<DSSDocument> archiveManifests) {
		String suffix = Utils.isCollectionEmpty(archiveManifests) ? Utils.EMPTY_STRING : String.valueOf(archiveManifests.size());
		return ZIP_ENTRY_ASICE_METAINF_CADES_ARCHIVE_MANIFEST + suffix + ARCHIVE_MANIFEST_EXTENSION;
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

	private boolean isAddASiCArchiveManifest(ASiCWithCAdESSignatureParameters parameters) {
		return SignatureLevel.CAdES_BASELINE_LTA == parameters.getSignatureLevel() && ASiCContainerType.ASiC_E == parameters.aSiC().getContainerType();
	}

	@Override
	protected String getExpectedSignatureExtension() {
		return ".p7s";
	}

}
