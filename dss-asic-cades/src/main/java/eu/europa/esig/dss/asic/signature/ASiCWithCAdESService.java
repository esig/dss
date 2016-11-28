package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
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
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

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

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		if (ASiCUtils.isASiCE(asicParameters)) {
			cadesParameters.setDetachedContent(null); // TODO ???
		}
		return getCAdESService().getDataToSign(contextToSignDocument, cadesParameters);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, ASiCWithCAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {

		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);
		assertSigningDateInCertificateValidityRange(parameters);

		DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		if (ASiCUtils.isASiCE(asicParameters)) {
			cadesParameters.setDetachedContent(null);
		}
		final DSSDocument signature = getCAdESService().signDocument(contextToSignDocument, cadesParameters, signatureValue);

		DSSDocument asicContainer = null;
		final boolean signingContainer = asicParameters.getEnclosedSignature() != null;
		if (signingContainer) {
			asicContainer = toSignDocument;
		}
		if (ASiCUtils.isASiCE(asicParameters)) {
			if (!signingContainer) {
				contextToSignDocument = toSignDocument;
			} else {
				contextToSignDocument = parameters.getDetachedContent();
			}
		}
		final InMemoryDocument asicSignature = buildASiCContainer(contextToSignDocument, asicContainer, parameters, signature);
		asicSignature.setName(
				DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
		final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, parameters.getDetachedContent());
		cadesParameters.setDetachedContent(detachedContents);
		final DSSDocument signature = subordinatedValidator.getDocument();
		final DSSDocument signedDocument = getCAdESService().extendDocument(signature, cadesParameters);

		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		ZipInputStream zis = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);
			zis = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (ASiCUtils.isMimetype(name)) {
					storeMimetype(parameters.aSiC(), zos);
				} else if (ASiCUtils.isCAdES(name)) {
					zos.putNextEntry(newEntry);
					final InputStream inputStream = signedDocument.openStream();
					Utils.copy(inputStream, zos);
					Utils.closeQuietly(inputStream);
				} else {
					zos.putNextEntry(newEntry);
					Utils.copy(zis, zos);
				}
			}
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(zos);
			Utils.closeQuietly(baos);
		}

		DSSDocument asicSignature = new InMemoryDocument(baos.toByteArray(), null, toExtendDocument.getMimeType());
		asicSignature.setName(
				DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		return asicSignature;
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final ASiCWithCAdESSignatureParameters parameters) {

		// detachedDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = detachedDocument;
		ASiCParameters asicParameters = parameters.aSiC();
		final DocumentValidator validator = getAsicValidator(detachedDocument);
		if (validator != null) {

			// This is already an existing ASiC container; a new signature should be added.
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DSSDocument contextSignature = subordinatedValidator.getDocument();
			DSSDocument signature = contextSignature;
			DocumentValidator documentValidator = subordinatedValidator;
			while (documentValidator.getNextValidator() != null) {
				documentValidator = documentValidator.getNextValidator();
				signature.setNextDocument(documentValidator.getDocument());
				signature = signature.getNextDocument();
			}

			asicParameters.setEnclosedSignature(contextSignature);
			if (ASiCUtils.isASiCE(asicParameters)) {
				contextToSignDocument = parameters.getDetachedContent();
			} else {
				contextToSignDocument = copyDetachedContent(parameters, subordinatedValidator);
			}
		} else {
			parameters.setDetachedContent(contextToSignDocument);
		}
		return contextToSignDocument;
	}

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument signDocument, final ASiCWithCAdESSignatureParameters parameters,
			final DSSDocument signature) throws DSSException {

		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);

			ASiCParameters asicParameters = parameters.aSiC();
			boolean asice = ASiCUtils.isASiCE(asicParameters);

			if (asice && (signDocument != null)) {
				copyZipContent(signDocument, zos);
			} else {
				if (signDocument != null) {
					copyMetaInfContent(signDocument, zos);
				}
				String toSignDocumentName = toSignDocument.getName();
				storeZipComment(asicParameters, zos, toSignDocumentName);
				storeMimetype(asicParameters, zos);
			}
			storeSignedFiles(toSignDocument, zos);
			storeSignature(asicParameters, signature, zos);

			if (asice) {
				storeAsicManifestCAdES(parameters, toSignDocument, zos);
			}
			Utils.closeQuietly(zos);

			final InMemoryDocument asicContainer = createASiCContainer(asicParameters, baos);
			return asicContainer;
		} catch (IOException e) {
			throw new DSSException("Unable to build the ASiC Container", e);
		} finally {
			Utils.closeQuietly(baos);
		}
	}

	private void storeSignature(ASiCParameters asicParameters, DSSDocument signature, ZipOutputStream zos) throws IOException {
		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		zos.putNextEntry(entrySignature);
		signature.writeTo(zos);
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

	private void storeAsicManifestCAdES(ASiCWithCAdESSignatureParameters parameters, final DSSDocument detachedDocument, final ZipOutputStream zos)
			throws IOException {

		ASiCParameters asicParameters = parameters.aSiC();

		final String signatureName = getSignatureFileName(asicParameters);
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature);
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		zos.putNextEntry(entrySignature);

		ASiCEWithCAdESManifestBuilder manifestBuilder = new ASiCEWithCAdESManifestBuilder(detachedDocument, parameters.getDigestAlgorithm(), signatureName);
		Document document = manifestBuilder.build();
		DomUtils.writeDocumentTo(document, zos);
	}

	private void copyMetaInfContent(DSSDocument toSignAsicContainer, ZipOutputStream zos) throws IOException {
		InputStream is = null;
		ZipInputStream zis = null;
		try {
			is = toSignAsicContainer.openStream();
			zis = new ZipInputStream(is);
			ZipEntry entry = null;
			while ((entry = zis.getNextEntry()) != null) {
				if (entry.getName().contains(META_INF)) {
					zos.putNextEntry(entry);
					Utils.copy(zis, zos);
				}
			}
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(is);
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
