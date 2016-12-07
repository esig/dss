package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.GetDataToSignHelper;
import eu.europa.esig.dss.asic.validation.ASiCEWithCAdESManifestValidator;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocuments, asicParameters);

		GetDataToSignHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

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

		GetDataToSignHelper dataToSignHelper = ASiCWithCAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifests = dataToSignHelper.getManifestFiles();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.setDetachedContents(dataToSignHelper.getDetachedContents());
		final DSSDocument signature = getCAdESService().signDocument(dataToSignHelper.getToBeSigned(), cadesParameters, signatureValue);
		String newSignatureFileName = dataToSignHelper.getSignatureFilename();
		signature.setName(dataToSignHelper.getSignatureFilename());

		if (ASiCUtils.isASiCS(asicParameters)) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFileName, iterator.next().getName())) {
					iterator.remove(); // remove existing file to be replaced
				}
			}
		}
		signatures.add(signature);

		final DSSDocument asicSignature = buildASiCContainer(dataToSignHelper.getSignedDocuments(), signatures, manifests, asicParameters);
		asicSignature
				.setName(DSSUtils.getFinalFileName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	private DSSDocument buildASiCContainer(List<DSSDocument> documentsToBeSigned, List<DSSDocument> signatures, List<DSSDocument> manifestDocuments,
			ASiCParameters asicParameters) {

		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);

			if (ASiCUtils.isASiCE(asicParameters)) {
				storeASICEManifest(manifestDocuments, zos);
			}

			storeSignatures(signatures, zos);
			storeSignedFiles(documentsToBeSigned, zos);
			storeMimetype(asicParameters, zos);
			storeZipComment(asicParameters, zos);

		} catch (IOException e) {
			throw new DSSException("Unable to build the ASiC Container", e);
		} finally {
			Utils.closeQuietly(zos);
			Utils.closeQuietly(baos);
		}

		return new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		if (!ASiCUtils.isArchive(toExtendDocument)) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		List<DSSDocument> manifests = getEmbeddedManifests();
		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();
		DSSDocument mimetype = getEmbeddedMimetype();

		ASiCContainerType containerType = ASiCUtils.getContainerType(toExtendDocument, mimetype, null);
		if (containerType == null) {
			throw new DSSException("Unable to determine container type");
		}

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

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

	@Override
	void storeSignatures(List<DSSDocument> signatures, ZipOutputStream zos) throws IOException {
		for (DSSDocument signature : signatures) {
			final ZipEntry entrySignature = new ZipEntry(signature.getName());
			zos.putNextEntry(entrySignature);
			signature.writeTo(zos);
		}
	}

	@Override
	boolean isSignatureFilename(String name) {
		return ASiCUtils.isCAdES(name);
	}

	@Override
	AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithCAdESContainerExtractor(archive);
	}

	private void storeASICEManifest(List<DSSDocument> manifestDocuments, ZipOutputStream zos) throws IOException {
		for (DSSDocument manifestDocument : manifestDocuments) {
			final ZipEntry entrySignature = new ZipEntry(manifestDocument.getName());
			zos.putNextEntry(entrySignature);
			manifestDocument.writeTo(zos);
		}
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
		return (isMimetypeCorrect && isSignatureTypeCorrect);
	}

}
