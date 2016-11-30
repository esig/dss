package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);

		boolean archive = ASiCUtils.isArchive(toSignDocument);
		if (archive) {
			extractCurrentArchive(toSignDocument);
		}

		List<DSSDocument> docs = getToBeSigned(toSignDocument, archive, asicParameters);
		DSSDocument toBeSigned = null;
		if (ASiCUtils.isASiCE(asicParameters)) {
			toBeSigned = getASiCManifest(docs, parameters);
		} else {
			toBeSigned = docs.get(0);
		}

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		return getCAdESService().getDataToSign(toBeSigned, cadesParameters);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, ASiCWithCAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {

		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);
		assertSigningDateInCertificateValidityRange(parameters);

		boolean archive = ASiCUtils.isArchive(toSignDocument);
		if (archive) {
			extractCurrentArchive(toSignDocument);
		}

		List<DSSDocument> signatures = getEmbeddedSignatures();
		List<DSSDocument> manifests = getEmbeddedManifests();

		List<DSSDocument> documentsToBeSigned = getToBeSigned(toSignDocument, archive, asicParameters);
		DSSDocument toBeSigned = null;
		if (ASiCUtils.isASiCE(asicParameters)) {
			DSSDocument manifest = getASiCManifest(documentsToBeSigned, parameters);
			manifests.add(manifest);
			toBeSigned = manifest; // ASiC-E, we sign the manifest which contains the digests of the documents
		} else {
			toBeSigned = documentsToBeSigned.get(0);
		}

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		final DSSDocument signature = getCAdESService().signDocument(toBeSigned, cadesParameters, signatureValue);
		String newSignatureFileName = getSignatureFileName(asicParameters, signatures);
		signature.setName(newSignatureFileName);

		if (ASiCUtils.isASiCS(asicParameters)) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFileName, iterator.next().getName())) {
					iterator.remove(); // remove existing file to be replaced
				}
			}
		}
		signatures.add(signature);

		final DSSDocument asicSignature = buildASiCContainer(documentsToBeSigned, signatures, manifests, asicParameters);
		asicSignature.setName(
				DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
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

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		for (DSSDocument signature : signatureDocuments) {
			CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
			DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
			extendedDocuments.add(extendDocument);
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

	private List<DSSDocument> getToBeSigned(DSSDocument toSignDocument, boolean archive, ASiCParameters asicParameters) {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		if (ASiCUtils.isASiCS(asicParameters)) {
			if (archive) {
				List<DSSDocument> embeddedSignedDocuments = getEmbeddedSignedDocuments();
				int nbDocs = Utils.collectionSize(embeddedSignedDocuments);
				if (nbDocs != 1) {
					throw new DSSException("Invalid ASiC-S container (" + nbDocs + " signed document(s) instead of 1)");
				}
				documents.addAll(embeddedSignedDocuments);
			} else {
				// ASiC-S -> 1 file (or zip with multi files)
				documents.add(toSignDocument);
			}
		} else {
			if (archive) {
				List<DSSDocument> embeddedSignedDocuments = getEmbeddedSignedDocuments();
				documents.addAll(embeddedSignedDocuments);
			} else {
				// TODO
				documents.add(toSignDocument);
			}
		}
		return documents;
	}

	private DSSDocument getASiCManifest(List<DSSDocument> documents, ASiCWithCAdESSignatureParameters parameters) {
		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(documents, parameters.getDigestAlgorithm(),
				getSignatureFileName(parameters.aSiC(), getEmbeddedSignatures()));

		DSSDocument manifest = null;
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			DomUtils.writeDocumentTo(manifestBuilder.build(), baos);
			String name = getASiCManifestFilename(getEmbeddedManifests());
			manifest = new InMemoryDocument(baos.toByteArray(), name, MimeType.XML);
		} finally {
			Utils.closeQuietly(baos);
		}
		return manifest;
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

	private void storeASICEManifest(List<DSSDocument> manifestDocuments, ZipOutputStream zos) throws IOException {
		for (DSSDocument manifestDocument : manifestDocuments) {
			final ZipEntry entrySignature = new ZipEntry(manifestDocument.getName());
			zos.putNextEntry(entrySignature);
			manifestDocument.writeTo(zos);
		}
	}

	private String getSignatureFileName(final ASiCParameters asicParameters, List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}
		final boolean asice = ASiCUtils.isASiCE(asicParameters);
		if (asice) {
			if (Utils.isCollectionNotEmpty(existingSignatures)) {
				return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace("001", getSignatureNumber(existingSignatures));
			} else {
				return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE;
			}
		} else {
			return ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE;
		}
	}

	private String getASiCManifestFilename(List<DSSDocument> existingManifests) {
		String suffix = Utils.isCollectionEmpty(existingManifests) ? Utils.EMPTY_STRING : String.valueOf(existingManifests.size());
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		return asicManifestZipEntryName;
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
	boolean canBeSigned(DSSDocument toSignDocument, ASiCParameters asicParameters) {
		boolean isMimetypeCorrect = true;
		boolean isSignatureTypeCorrect = true;
		if (ASiCUtils.isArchive(toSignDocument)) {
			String expectedMimeType = toSignDocument.getMimeType().getMimeTypeString();
			String mimeTypeFromParameter = ASiCUtils.getMimeTypeString(asicParameters);
			isMimetypeCorrect = Utils.areStringsEqualIgnoreCase(expectedMimeType, mimeTypeFromParameter);
			if (isMimetypeCorrect) {
				isSignatureTypeCorrect = ASiCUtils.isArchiveContainsCorrectSignatureExtension(toSignDocument, ".p7s");
			}
		}
		return (isMimetypeCorrect && isSignatureTypeCorrect);
	}

}
