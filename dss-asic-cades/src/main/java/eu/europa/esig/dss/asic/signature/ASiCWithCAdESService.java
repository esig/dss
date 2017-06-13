package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
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

@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP = "META-INF/timestamp001.tst";

	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocuments, asicParameters);

		GetDataToSignASiCWithCAdESHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());
		return getCAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), cadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {

		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocuments, asicParameters);
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

			DSSDocument archiveManfest = ASiCUtils.createDssDocumentFromDomDocument(builder.build(), getArchivManifestFilename(archiveManifests));
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
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		if (!ASiCUtils.isASiCContainer(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureExtension(toExtendDocument, ".p7s")) {
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

		boolean addASiCArchiveManifest = isAddASiCArchiveManifest(parameters);

		for (DSSDocument signature : signatureDocuments) {

			if (ASiCContainerType.ASiC_E == containerType) {

				ASiCEWithCAdESManifestValidator manifestValidator = new ASiCEWithCAdESManifestValidator(signature, manifests, signedDocuments);
				DSSDocument linkedManifest = manifestValidator.getLinkedManifest();

				if (linkedManifest != null) {
					String originalName = signature.getName();
					CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
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
				CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
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

			DSSDocument archiveManfest = ASiCUtils.createDssDocumentFromDomDocument(builder.build(), getArchivManifestFilename(archiveManifests));
			extendedDocuments.add(archiveManfest);

			DigestAlgorithm digestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
			TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, DSSUtils.digest(digestAlgorithm, archiveManfest));
			DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST);
			extendedDocuments.add(timestamp);
		}

		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			copyExistingArchiveWithSignatureList(toExtendDocument, extendedDocuments, baos);
		} finally {
			Utils.closeQuietly(baos);
		}

		DSSDocument asicSignature = new InMemoryDocument(baos.toByteArray(), null, toExtendDocument.getMimeType());
		asicSignature.setName(
				DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		return asicSignature;
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
	boolean canBeSigned(List<DSSDocument> toSignDocuments, ASiCParameters asicParameters) {
		boolean isMimetypeCorrect = true;
		boolean isSignatureTypeCorrect = true;
		if (ASiCUtils.isArchive(toSignDocuments)) {
			DSSDocument archiveDoc = toSignDocuments.get(0);
			String expectedMimeType = archiveDoc.getMimeType().getMimeTypeString();
			String mimeTypeFromParameter = ASiCUtils.getMimeTypeString(asicParameters);
			isMimetypeCorrect = Utils.areStringsEqualIgnoreCase(expectedMimeType, mimeTypeFromParameter);
			if (isMimetypeCorrect) {
				isSignatureTypeCorrect = ASiCUtils.isArchiveContainsCorrectSignatureExtension(archiveDoc, ".p7s");
			}
		}
		return isMimetypeCorrect && isSignatureTypeCorrect;
	}

}
