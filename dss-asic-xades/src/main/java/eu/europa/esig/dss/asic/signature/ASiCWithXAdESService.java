package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
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
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";

	static {
		DSSXMLUtils.registerNamespace("asic", ASiCNamespace.ASiC);
	}

	public ASiCWithXAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with XAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		return getXAdESService().getDataToSign(contextToSignDocument, getXAdESParameters(parameters));
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);
		assertSigningDateInCertificateValidityRange(parameters);

		DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		XAdESService xadesService = getXAdESService();
		final DSSDocument signature = xadesService.signDocument(contextToSignDocument, getXAdESParameters(parameters), signatureValue);

		DSSDocument asicContainer = null;
		final boolean signingContainer = asicParameters.getEnclosedSignature() != null;
		if (signingContainer) {
			asicContainer = toSignDocument;
		}

		final InMemoryDocument asicSignature = buildASiCContainer(contextToSignDocument, asicContainer, parameters, signature);
		asicSignature.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
		final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();

		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters);
		final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, parameters.getDetachedContent());
		xadesParameters.setDetachedContent(detachedContents);
		final DSSDocument signature = subordinatedValidator.getDocument();
		final DSSDocument signedDocument = getXAdESService().extendDocument(signature, xadesParameters);

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
				} else if (ASiCUtils.isXAdES(name)) {
					zos.putNextEntry(newEntry);
					final InputStream inputStream = signedDocument.openStream();
					Utils.copy(inputStream, zos);
					Utils.closeQuietly(inputStream);
				} else {
					zos.putNextEntry(newEntry);
					Utils.copy(zis, zos);
				}
			}
			Utils.closeQuietly(zos);
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(baos);
		}

		DSSDocument asicSignature = new InMemoryDocument(baos.toByteArray(), null, toExtendDocument.getMimeType());
		asicSignature.setName(DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
		return asicSignature;
	}

	private DSSDocument getDetachedContents(final DocumentValidator subordinatedValidator, DSSDocument originalDocument) {

		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		if ((detachedContents == null) || (detachedContents.size() == 0)) {

			final List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
			DSSDocument currentDocument = originalDocument;
			do {
				detachedContentsList.add(currentDocument);
				subordinatedValidator.setDetachedContents(detachedContentsList);
				currentDocument = currentDocument.getNextDocument();
			} while (currentDocument != null);
		} else {
			originalDocument = null;
			DSSDocument lastDocument = null;
			for (final DSSDocument currentDocument : detachedContents) {
				if (ASiCUtils.isASiCManifest(currentDocument.getName())) {
					originalDocument = currentDocument;
					lastDocument = currentDocument;
				}
			}
			if (originalDocument != null) {
				detachedContents.remove(originalDocument);
			}
			for (final DSSDocument currentDocument : detachedContents) {
				if (originalDocument == null) {
					originalDocument = currentDocument;
				} else {
					lastDocument.setNextDocument(currentDocument);
				}
				lastDocument = currentDocument;
			}

		}
		return originalDocument;
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final ASiCWithXAdESSignatureParameters parameters) {

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

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument signDocument, final ASiCWithXAdESSignatureParameters parameters,
			final DSSDocument signature) {
		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);

			ASiCParameters asicParameters = parameters.aSiC();

			final String toSignDocumentName = toSignDocument.getName();

			boolean asice = ASiCUtils.isASiCE(asicParameters);
			if (asice && (signDocument != null)) {
				copyZipContent(signDocument, zos);
			} else {
				storeZipComment(asicParameters, zos, toSignDocumentName);
				storeMimetype(asicParameters, zos);
			}
			storeSignedFiles(toSignDocument, zos);
			storeSignature(asicParameters, signature, zos);

			if (asice && signDocument == null) { // only one manifest file / zip
				storeASICEManifest(toSignDocument, zos);
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
		Document xmlSignatureDoc = DomUtils.buildDOM(signature);
		DomUtils.writeDocumentTo(xmlSignatureDoc, zos);
	}

	private String getSignatureFileName(final ASiCParameters asicParameters) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}
		final boolean asice = ASiCUtils.isASiCE(asicParameters);
		if (asice) {
			if (asicParameters.getEnclosedSignature() != null) {
				return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE.replace("001", getSignatureNumber(asicParameters.getEnclosedSignature()));
			} else {
				return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE;
			}
		} else {
			return ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE;
		}
	}

	private void storeASICEManifest(final DSSDocument detachedDocument, final ZipOutputStream zos) throws IOException {
		final String asicManifestZipEntryName = META_INF + "manifest.xml";
		final ZipEntry entry = new ZipEntry(asicManifestZipEntryName);
		zos.putNextEntry(entry);
		ASiCEWithXAdESManifestBuilder manifestBuilder = new ASiCEWithXAdESManifestBuilder(detachedDocument);
		DomUtils.writeDocumentTo(manifestBuilder.build(), zos);
	}

	private XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(tspSource);
		return xadesService;
	}

	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters) {
		XAdESSignatureParameters xadesParameters = parameters;
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return xadesParameters;
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
				isSignatureTypeCorrect = ASiCUtils.isArchiveContainsCorrectSignatureExtension(toSignDocument, ".xml");
			}
		}
		return (isMimetypeCorrect && isSignatureTypeCorrect);
	}

}
