package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.ASiCNamespaces;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ASiCWithXAdESService extends AbstractSignatureService<ASiCWithXAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";

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

	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters) {
		XAdESSignatureParameters xadesParameters = parameters;
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return xadesParameters;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		// TODO Auto-generated method stub
		return null;
	}

	private void assertCanBeSign(DSSDocument toSignDocument, final ASiCParameters asicParameters) {
		if (!canBeSigned(toSignDocument, asicParameters)) { // First verify if the file can be signed
			throw new DSSUnsupportedOperationException("You only can sign an ASiC container by using the same type of container and of signature");
		}
	}

	private XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(tspSource);
		return xadesService;
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final ASiCWithXAdESSignatureParameters parameters) {

		// detachedDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = detachedDocument;
		ASiCParameters asicParameters = parameters.aSiC();
		final boolean asice = ASiCUtils.isASiCE(asicParameters);
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
			if (asice) {
				contextToSignDocument = parameters.getDetachedContent();
			} else {
				contextToSignDocument = copyDetachedContent(parameters, subordinatedValidator);
			}
		} else {
			parameters.setDetachedContent(contextToSignDocument);
		}
		return contextToSignDocument;
	}

	private DocumentValidator getAsicValidator(final DSSDocument toSignDocument) {
		if (ASiCUtils.isASiCContainer(toSignDocument)) {
			return SignedDocumentValidator.fromDocument(toSignDocument);
		}
		return null;
	}

	private DSSDocument copyDetachedContent(final AbstractSignatureParameters underlyingParameters, final DocumentValidator subordinatedValidator) {
		DSSDocument contextToSignDocument = null;
		DSSDocument currentDetachedDocument = null;
		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		for (final DSSDocument detachedDocument : detachedContents) {
			if (contextToSignDocument == null) {
				contextToSignDocument = detachedDocument;
			} else {
				currentDetachedDocument.setNextDocument(detachedDocument);
			}
			currentDetachedDocument = detachedDocument;
		}
		underlyingParameters.setDetachedContent(contextToSignDocument);
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
				storeManifestXAdES(toSignDocument, zos);
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

	private InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream baos) {
		return new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
	}

	private void storeSignedFiles(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws IOException {
		DSSDocument currentDetachedDocument = detachedDocument;
		do {
			InputStream is = null;
			try {
				final String detachedDocumentName = currentDetachedDocument.getName();
				final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				outZip.setLevel(ZipEntry.DEFLATED);

				outZip.putNextEntry(entryDocument);
				is = currentDetachedDocument.openStream();
				Utils.copy(is, outZip);
			} finally {
				Utils.closeQuietly(is);
			}
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
	}

	private void storeSignature(ASiCParameters asicParameters, DSSDocument signature, ZipOutputStream zipOutputStream) throws IOException {
		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		zipOutputStream.putNextEntry(entrySignature);
		Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
		storeXmlDom(zipOutputStream, xmlSignatureDoc);
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

	private String getSignatureNumber(DSSDocument enclosedSignature) {
		int signatureNumbre = 1;
		while (enclosedSignature != null) {
			signatureNumbre++;
			enclosedSignature = enclosedSignature.getNextDocument();
		}
		String sigNumberStr = String.valueOf(signatureNumbre);
		String zeroPad = "000";
		return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

	private void storeManifestXAdES(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws IOException {
		final String asicManifestZipEntryName = META_INF + "manifest.xml";
		final ZipEntry entry = new ZipEntry(asicManifestZipEntryName);
		outZip.putNextEntry(entry);
		buildAsicManifestXAdES(detachedDocument, outZip);
	}

	// <?xml version="1.0" encoding="UTF-8" standalone="no" ?>
	// <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">>
	// <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
	// <manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
	// <manifest:file-entry manifest:full-path="test-data-file.bin" manifest:media-type="application/octet-stream"/>
	// </manifest:manifest>
	private void buildAsicManifestXAdES(DSSDocument detachedDocument, OutputStream outputStream) {
		final Document documentDom = DSSXMLUtils.buildDOM();
		final Element manifestDom = documentDom.createElementNS(ASiCNamespaces.MANIFEST_NS, "manifest:manifest");
		documentDom.appendChild(manifestDom);

		final Element rootDom = DSSXMLUtils.addElement(documentDom, manifestDom, ASiCNamespaces.MANIFEST_NS, "manifest:file-entry");
		rootDom.setAttribute("manifest:full-path", "/");
		rootDom.setAttribute("manifest:media-type", MimeType.ASICE.getMimeTypeString());

		DSSDocument currentDetachedDocument = detachedDocument;
		do {
			Element fileDom = DSSXMLUtils.addElement(documentDom, manifestDom, ASiCNamespaces.MANIFEST_NS, "manifest:file-entry");
			fileDom.setAttribute("manifest:full-path", currentDetachedDocument.getName());
			fileDom.setAttribute("manifest:media-type", currentDetachedDocument.getMimeType().getMimeTypeString());

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

		storeXmlDom(outputStream, documentDom);
	}

	private void storeXmlDom(final OutputStream outZip, final Document xml) throws DSSException {
		try {
			final DOMSource xmlSource = new DOMSource(xml);
			final StreamResult outputTarget = new StreamResult(outZip);
			Transformer transformer = DSSXMLUtils.getSecureTransformer();
			transformer.transform(xmlSource, outputTarget);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) throws IOException {
		InputStream is = null;
		ZipInputStream zis = null;
		try {
			is = toSignAsicContainer.openStream();
			zis = new ZipInputStream(is);
			ZipEntry entry = null;
			while ((entry = zis.getNextEntry()) != null) {
				zipOutputStream.putNextEntry(entry);
				Utils.copy(zis, zipOutputStream);
			}
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(is);
		}
	}

	private void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream outZip, final String toSignDocumentName) {
		if (asicParameters.isZipComment() && Utils.isStringNotEmpty(toSignDocumentName)) {
			outZip.setComment("mimetype=" + ASiCUtils.getMimeTypeString(asicParameters));
		}
	}

	private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip) throws IOException {
		final byte[] mimeTypeBytes = ASiCUtils.getMimeTypeString(asicParameters).getBytes("UTF-8");
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);
		outZip.putNextEntry(entryMimetype);
		Utils.write(mimeTypeBytes, outZip);
	}

	private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {
		final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
		entryMimetype.setMethod(ZipEntry.STORED);
		entryMimetype.setSize(mimeTypeBytes.length);
		entryMimetype.setCompressedSize(mimeTypeBytes.length);
		final CRC32 crc = new CRC32();
		crc.update(mimeTypeBytes);
		entryMimetype.setCrc(crc.getValue());
		return entryMimetype;
	}

	private boolean canBeSigned(DSSDocument toSignDocument, ASiCParameters asicParameters) {
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
