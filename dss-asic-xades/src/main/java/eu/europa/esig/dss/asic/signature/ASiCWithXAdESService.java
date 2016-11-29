package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.ASiC);
	}

	public ASiCWithXAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with XAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);

		DSSDocument existingXAdESSignatureASiCS = null;
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		if (ASiCUtils.isArchive(toSignDocument)) {
			// If archive, we copy the documents to be signed
			extractCurrentArchive(toSignDocument);
			documents.addAll(getEmbeddedSignedDocuments());
			List<DSSDocument> embeddedSignatures = getEmbeddedSignedDocuments();
			if (ASiCUtils.isASiCS(asicParameters) && Utils.collectionSize(embeddedSignatures) == 1) {
				existingXAdESSignatureASiCS = embeddedSignatures.get(0);
			}
		} else {
			documents.add(toSignDocument);
		}

		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, existingXAdESSignatureASiCS);
		xadesParameters.setDetachedContents(documents);

		return getXAdESService().getDataToSign(toSignDocument, xadesParameters);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocument, asicParameters);
		assertSigningDateInCertificateValidityRange(parameters);

		boolean isArchive = ASiCUtils.isArchive(toSignDocument);

		DSSDocument existingXAdESSignatureASiCS = null;
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		List<DSSDocument> signatures = new ArrayList<DSSDocument>();
		if (isArchive) {
			// If archive, we copy the documents to be signed
			extractCurrentArchive(toSignDocument);
			documents.addAll(getEmbeddedSignedDocuments());

			signatures = getEmbeddedSignedDocuments();
			if (ASiCUtils.isASiCS(asicParameters) && Utils.collectionSize(signatures) == 1) {
				existingXAdESSignatureASiCS = signatures.get(0);
			}

		} else {
			documents.add(toSignDocument);
		}

		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, existingXAdESSignatureASiCS);
		xadesParameters.setDetachedContents(documents);
		final DSSDocument newSignature = getXAdESService().signDocument(toSignDocument, xadesParameters, signatureValue);
		newSignature.setName(getSignatureFileName(asicParameters, signatures));

		if (existingXAdESSignatureASiCS != null) {
			signatures.remove(existingXAdESSignatureASiCS);
		}
		signatures.add(newSignature);

		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			if (isArchive) {
				copyExistingArchiveWithSignatureList(toSignDocument, signatures, baos);
			} else {
				buildASiCContainer(documents, signatures, asicParameters, baos);
			}
		} finally {
			Utils.closeQuietly(baos);
		}

		final InMemoryDocument asicSignature = new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
		asicSignature.setName(
				DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		if (!ASiCUtils.isArchive(toExtendDocument)) {
			throw new DSSException("Unsupported file type");
		}

		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		for (DSSDocument signature : signatureDocuments) {
			XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, null);
			xadesParameters.setDetachedContents(signedDocuments);
			DSSDocument extendDocument = getXAdESService().extendDocument(signature, xadesParameters);
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

	private void copyExistingArchiveWithSignatureList(DSSDocument archiveDocument, List<DSSDocument> signaturesToAdd, ByteArrayOutputStream baos) {
		ZipOutputStream zos = null;
		try {
			zos = new ZipOutputStream(baos);
			copyArchiveContentWithoutSignatures(archiveDocument, zos);
			storeSignatures(signaturesToAdd, zos);
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		} finally {
			Utils.closeQuietly(zos);
		}
	}

	private void copyArchiveContentWithoutSignatures(DSSDocument archiveDocument, ZipOutputStream zos) throws IOException {
		ZipInputStream zis = null;
		try {
			zis = new ZipInputStream(archiveDocument.openStream());
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (!ASiCUtils.isXAdES(name)) {
					zos.putNextEntry(newEntry);
					Utils.copy(zis, zos);
				}
			}
		} finally {
			Utils.closeQuietly(zis);
		}
	}

	private void buildASiCContainer(List<DSSDocument> documents, List<DSSDocument> signatures, ASiCParameters asicParameters, ByteArrayOutputStream baos) {
		ZipOutputStream zos = null;
		try {
			zos = new ZipOutputStream(baos);

			if (ASiCUtils.isASiCE(asicParameters)) {
				storeASICEManifest(documents, zos);
			}

			storeSignatures(signatures, zos);
			storeSignedFiles(documents, zos);
			storeMimetype(asicParameters, zos);
			storeZipComment(asicParameters, zos);

		} catch (IOException e) {
			throw new DSSException("Unable to build the ASiC Container", e);
		} finally {
			Utils.closeQuietly(zos);
		}
	}

	private void storeSignatures(List<DSSDocument> signatures, ZipOutputStream zos) throws IOException {
		for (DSSDocument dssDocument : signatures) {
			ZipEntry entrySignature = new ZipEntry(dssDocument.getName());
			zos.putNextEntry(entrySignature);
			Document xmlSignatureDoc = DomUtils.buildDOM(dssDocument);
			DomUtils.writeDocumentTo(xmlSignatureDoc, zos);
		}
	}

	private String getSignatureFileName(final ASiCParameters asicParameters, List<DSSDocument> existingSignatures) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}
		final boolean asice = ASiCUtils.isASiCE(asicParameters);
		if (asice) {
			if (Utils.isCollectionNotEmpty(existingSignatures)) {
				return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE.replace("001", getSignatureNumber(existingSignatures));
			} else {
				return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE;
			}
		} else {
			return ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE;
		}
	}

	private void storeASICEManifest(final List<DSSDocument> documentsToBeSigned, final ZipOutputStream zos) throws IOException {
		final ZipEntry entry = new ZipEntry(META_INF + "manifest.xml");
		zos.putNextEntry(entry);
		ASiCEWithXAdESManifestBuilder manifestBuilder = new ASiCEWithXAdESManifestBuilder(documentsToBeSigned);
		DomUtils.writeDocumentTo(manifestBuilder.build(), zos);
	}

	private XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(tspSource);
		return xadesService;
	}

	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters, DSSDocument existingXAdESSignatureASiCS) {
		XAdESSignatureParameters xadesParameters = parameters;
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		Document rootDocument = null;
		// If ASiC-S + already existing signature file, we re-use the same signature file
		if (existingXAdESSignatureASiCS != null) {
			rootDocument = DomUtils.buildDOM(existingXAdESSignatureASiCS);
		} else {
			rootDocument = DomUtils.createDocument(ASiCNamespace.ASiC, ASiCNamespace.XADES_SIGNATURES);
		}
		xadesParameters.setRootDocument(rootDocument);
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
