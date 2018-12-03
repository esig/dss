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
package eu.europa.esig.dss.asic.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.signature.asice.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.validation.ASiCEWithCAdESManifestValidator;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.TimestampToken;

@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP = "META-INF/timestamp001.tst";

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
			ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(signatures, dataToSignHelper.getSignedDocuments(),
					manifests, parameters.getArchiveTimestampParameters().getDigestAlgorithm(), timestampFilename);

			DSSDocument archiveManfest = DomUtils.createDssDocumentFromDomDocument(builder.build(), getArchivManifestFilename(archiveManifests));
			signatures.add(archiveManfest);

			DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
			TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManfest));
			DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST);
			signatures.add(timestamp);

			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		final DSSDocument asicSignature = buildASiCContainer(dataToSignHelper.getSignedDocuments(), signatures, manifests, asicParameters);
		asicSignature
				.setName(DSSUtils.getFinalFileName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
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
		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> archiveManifests = getEmbeddedArchiveManifests();
		List<DSSDocument> timestamps = getEmbeddedTimestamps();
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

			if (ASiCContainerType.ASiC_E == containerType) {

				ASiCEWithCAdESManifestValidator manifestValidator = new ASiCEWithCAdESManifestValidator(signature, manifests, signedDocuments);
				DSSDocument linkedManifest = manifestValidator.getLinkedManifest();

				if (linkedManifest != null) {
					String originalName = signature.getName();
					cadesParameters.setDetachedContents(Arrays.asList(linkedManifest));

					DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
					extendDocument.setName(originalName);
					extendedDocuments.add(extendDocument);
				} else {
					LOG.warn("Manifest not found for signature file '{}' -> NOT EXTENDED !!!", signature.getName());
					extendedDocuments.add(signature);
				}
			} else {
				String originalName = signature.getName();
				cadesParameters.setDetachedContents(signedDocuments);

				DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
				extendDocument.setName(originalName);
				extendedDocuments.add(extendDocument);
			}
		}

		if (addASiCArchiveManifest) {
			String timestampFilename = getArchiveTimestampFilename(timestamps);
			ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(extendedDocuments, signedDocuments, manifests,
					parameters.getArchiveTimestampParameters().getDigestAlgorithm(), timestampFilename);

			DSSDocument archiveManfest = DomUtils.createDssDocumentFromDomDocument(builder.build(), getArchivManifestFilename(archiveManifests));
			extendedDocuments.add(archiveManfest);

			DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
			TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManfest));
			DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST);
			extendedDocuments.add(timestamp);

			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments);
		extensionResult.setName(
				DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		return extensionResult;
	}

	private String getArchivManifestFilename(List<DSSDocument> archiveManifests) {
		String suffix = Utils.isCollectionEmpty(archiveManifests) ? Utils.EMPTY_STRING : String.valueOf(archiveManifests.size());
		return "META-INF/ASiCArchiveManifest" + suffix + ".xml";
	}

	private String getArchiveTimestampFilename(List<DSSDocument> timestamps) {
		int num = Utils.collectionSize(timestamps) + 1;
		return ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
	}

	@Override
	boolean isSignatureFilename(String name) {
		return ASiCUtils.isCAdES(name);
	}

	@Override
	AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
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
	String getExpectedSignatureExtension() {
		return ".p7s";
	}

}
