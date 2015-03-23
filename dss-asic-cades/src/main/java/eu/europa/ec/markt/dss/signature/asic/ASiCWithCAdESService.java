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
package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.ASiCNamespaces;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.parameter.ASiCWithCAdESSignatureParameters;
import eu.europa.ec.markt.dss.parameter.CAdESSignatureParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.validation.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCCMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;

/**
 * Implementation of {@code DocumentSignatureService} for ASiC-S and -E containers. It allows the creation of containers based on CAdES standard.
 *
 */
public class ASiCWithCAdESService extends AbstractSignatureService<ASiCWithCAdESSignatureParameters> {

	private final static Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	private final static String ASICS_EXTENSION = ".asics"; // can be ".scs"
	private final static String ASICE_EXTENSION = ".asice"; // can be ".sce"

	private CAdESService cadesService;

	/**
	 * This is the constructor to create an instance of the {@code ASiCService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public ASiCWithCAdESService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCWithCAdESService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		CAdESSignatureParameters cadesParameters = getParameters(parameters);
		CAdESService cadesService = getCAdESService();
		return cadesService.getDataToSign(contextToSignDocument, cadesParameters);
	}

	/**
	 * ETSI TS 102 918 v1.2.1 (2012-02) <br />
	 *
	 * Contents of Container ( 6.2.2 )
	 * </p>
	 * <ul>
	 * <li>The file extension ".asics" should be used .</li>
	 * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in clause
	 * A.5. Its the recommended format</li>
	 * <li>The comment field in the ZIP header may be used to identify the type of the data object within the container.
	 * <br />
	 * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
	 * the signed data object</li>
	 * <li>The mimetype file can be used to support operating systems that rely on some content in specific positions in
	 * a file.<br />
	 * <ul>
	 * <li>It has to be the first entry in the archive.</li>
	 * <li>It cannot contain "Extra fields".</li>
	 * <li>It cannot be compressed or encrypted inside the ZIP file</li>
	 * </ul>
	 * </li>
	 * </ul>
	 */
	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final ASiCWithCAdESSignatureParameters parameters, final byte[] signatureValue) throws DSSException {
		try {
			assertSigningDateInCertificateValidityRange(parameters);

			ASiCParameters asicParameters = parameters.aSiC();

			DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
			parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

			CAdESSignatureParameters cadesParameters = getParameters(parameters);
			CAdESService cadesService = getCAdESService();
			DSSDocument signature = cadesService.signDocument(contextToSignDocument, cadesParameters, signatureValue);

			DSSDocument asicContainer = null;
			final boolean signingContainer = asicParameters.getEnclosedSignature() != null;
			if (signingContainer) {
				asicContainer = toSignDocument;
			}
			if (isAsice(asicParameters)) {
				if (!signingContainer) {
					contextToSignDocument = toSignDocument;
				} else {
					contextToSignDocument = parameters.getDetachedContent();
				}
			}
			final InMemoryDocument asicSignature = buildASiCContainer(contextToSignDocument, asicContainer, parameters, signature);
			parameters.setDeterministicId(null);
			return asicSignature;

		} catch(IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final ASiCWithCAdESSignatureParameters parameters) throws DSSException {
		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new NullPointerException();
		}
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry privateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final ASiCWithCAdESSignatureParameters parameters) throws DSSException {

		try {
			final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			CAdESService cadesService = getCAdESService();

			final CAdESSignatureParameters cadesParameters = getParameters(parameters);
			final DSSDocument detachedContent = parameters.getDetachedContent();
			final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, detachedContent);
			cadesParameters.setDetachedContent(detachedContents);
			final DSSDocument signature = subordinatedValidator.getDocument();
			final DSSDocument signedDocument = cadesService.extendDocument(signature, cadesParameters);

			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final ZipOutputStream zipOutputStream = new ZipOutputStream(output);
			final ZipInputStream zipInputStream = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry;
			while ((entry = getNextZipEntry(zipInputStream)) != null) {

				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (ASiCContainerValidator.isMimetype(name)) {
					storeMimetype(parameters.aSiC(), zipOutputStream);
				} else if (ASiCContainerValidator.isXAdES(name) || ASiCContainerValidator.isCAdES(name)) {
					createZipEntry(zipOutputStream, newEntry);
					final InputStream inputStream = signedDocument.openStream();
					IOUtils.copy(inputStream, zipOutputStream);
					IOUtils.closeQuietly(inputStream);
				} else {
					createZipEntry(zipOutputStream, newEntry);
					IOUtils.copy(zipInputStream, zipOutputStream);
				}
			}
			IOUtils.closeQuietly(zipInputStream);
			IOUtils.closeQuietly(zipOutputStream);
			return new InMemoryDocument(output.toByteArray());

		} catch(IOException e) {
			throw new DSSException(e);
		}
	}

	private DSSDocument copyDetachedContent(final SignatureParameters underlyingParameters, final DocumentValidator subordinatedValidator) {
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

	private DocumentValidator getAsicValidator(final DSSDocument toSignDocument) {
		// Check if this is an existing container
		try {
			final DocumentValidator validator = SignedDocumentValidator.fromDocument(toSignDocument);
			if (isAsicValidator(validator)) {
				return validator;
			}
		} catch (Exception e) {
			// do nothing
		}
		return null;
	}

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument signDocument, final ASiCWithCAdESSignatureParameters parameters,
			final DSSDocument signature) throws IOException {

		ASiCParameters asicParameters = parameters.aSiC();

		final boolean asice = isAsice(asicParameters);

		final String toSignDocumentName = toSignDocument.getName();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		ZipOutputStream zipOutputStream = new ZipOutputStream(outBytes);

		if (asice && (signDocument != null)) {
			copyZipContent(signDocument, zipOutputStream);
		} else {
			storeZipComment(asicParameters, zipOutputStream, toSignDocumentName);
			storeMimetype(asicParameters, zipOutputStream);
		}

		storeSignedFiles(toSignDocument, zipOutputStream);

		buildCAdES(asicParameters, signature, zipOutputStream);

		if (asice) {
			storeAsicManifest(parameters, toSignDocument, zipOutputStream);
		}
		DSSUtils.close(zipOutputStream);

		final InMemoryDocument asicContainer = createASiCContainer(asicParameters, outBytes, toSignDocumentName);
		return asicContainer;
	}

	private void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) throws IOException {
		final InputStream inputStream = toSignAsicContainer.openStream();
		final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		for (ZipEntry entry = getNextZipEntry(zipInputStream); entry != null; entry = getNextZipEntry(zipInputStream)) {
			createZipEntry(zipOutputStream, entry);
			IOUtils.copy(zipInputStream, zipOutputStream);
		}
		IOUtils.closeQuietly(zipInputStream);
	}

	private void storeAsicManifest(ASiCWithCAdESSignatureParameters parameters, final DSSDocument detachedDocument, final ZipOutputStream outZip) {

		ASiCParameters asicParameters = parameters.aSiC();

		final String signatureName = getSignatureFileName(asicParameters);
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature + "signature".length());
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifest(parameters, detachedDocument, outZip);
	}

	private void buildAsicManifest(final ASiCWithCAdESSignatureParameters underlyingParameters, final DSSDocument detachedDocument, final OutputStream outputStream) {

		ASiCParameters asicParameters = underlyingParameters.aSiC();

		final Document documentDom = DSSXMLUtils.buildDOM();
		final Element asicManifestDom = documentDom.createElementNS(ASiCNamespaces.ASiC, "asic:ASiCManifest");
		documentDom.appendChild(asicManifestDom);

		final Element sigReferenceDom = DSSXMLUtils.addElement(documentDom, asicManifestDom, ASiCNamespaces.ASiC, "asic:SigReference");
		final String signatureName = getSignatureFileName(asicParameters);
		sigReferenceDom.setAttribute("URI", signatureName);
		final String signatureMimeType = getSignatureMimeType(asicParameters);
		sigReferenceDom.setAttribute("MimeType", signatureMimeType);

		DSSDocument currentDetachedDocument = detachedDocument;
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final Element dataObjectReferenceDom = DSSXMLUtils.addElement(documentDom, sigReferenceDom, ASiCNamespaces.ASiC, "asic:DataObjectReference");
			dataObjectReferenceDom.setAttribute("URI", detachedDocumentName);

			final Element digestMethodDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
			final DigestAlgorithm digestAlgorithm = underlyingParameters.getDigestAlgorithm();
			digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

			final Element digestValueDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
			final byte[] digest = DSSUtils.digest(digestAlgorithm, currentDetachedDocument.getBytes());
			final String base64Encoded = Base64.encodeBase64String(digest);
			final Text textNode = documentDom.createTextNode(base64Encoded);
			digestValueDom.appendChild(textNode);

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

		storeXmlDom(outputStream, documentDom);
	}

	private void createZipEntry(final ZipOutputStream outZip, final ZipEntry entrySignature) throws DSSException {
		try {
			outZip.putNextEntry(entrySignature);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream outBytes, final String toSignDocumentName) {
		final byte[] documentBytes = outBytes.toByteArray();
		final SignatureForm containerForm = asicParameters.getContainerForm();
		final boolean asics = SignatureForm.ASiC_S.equals(containerForm);
		final String extension = asics ? ASICS_EXTENSION : ASICE_EXTENSION;
		final String name = toSignDocumentName != null ? toSignDocumentName + extension : null;
		final MimeType mimeType = asics ? MimeType.ASICS : MimeType.ASICE;
		return new InMemoryDocument(documentBytes, name, mimeType);
	}

	private void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream outZip, final String toSignDocumentName) {
		if (asicParameters.isZipComment() && StringUtils.isNotEmpty(toSignDocumentName)) {
			outZip.setComment("mimetype=" + getMimeTypeBytes(asicParameters));
		}
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final ASiCWithCAdESSignatureParameters underlyingParameter) {

		// detachedDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = detachedDocument;
		ASiCParameters asicParameters = underlyingParameter.aSiC();
		final boolean asice = isAsice(asicParameters );
		final DocumentValidator validator = getAsicValidator(detachedDocument);
		if (isAsicValidator(validator)) {
			// This is already an existing ASiC container; a new signature should be added.
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DSSDocument contextSignature = subordinatedValidator.getDocument();
			asicParameters.setEnclosedSignature(contextSignature);
			if (asice) {
				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				buildAsicManifest(underlyingParameter, underlyingParameter.getDetachedContent(), outputStream);
				contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
				underlyingParameter.setDetachedContent(null);
			} else {
				contextToSignDocument = copyDetachedContent(underlyingParameter, subordinatedValidator);
			}
			if (!asice && (subordinatedValidator instanceof ASiCCMSDocumentValidator)) {
				contextToSignDocument = contextSignature;
			}
		} else {
			if (asice) {
				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				buildAsicManifest(underlyingParameter, detachedDocument, outputStream);
				contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
			} else {
				underlyingParameter.setDetachedContent(contextToSignDocument);
			}
		}
		return contextToSignDocument;
	}

	private boolean isAsicValidator(final DocumentValidator documentValidator) {
		final boolean result = (documentValidator != null) && (documentValidator instanceof ASiCContainerValidator);
		return result;
	}

	private ZipEntry getNextZipEntry(final ZipInputStream zipInputStream) throws DSSException {
		try {
			return zipInputStream.getNextEntry();
		} catch (IOException e) {
			throw new DSSException(e);
		}
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

	/**
	 * Creates a specific XAdES/CAdES signature parameters on the base of the provided parameters. Forces the signature packaging to
	 * DETACHED
	 *
	 * @param parameters must provide signingToken, PrivateKeyEntry and date
	 * @return new specific instance for XAdES or CAdES
	 */
	private CAdESSignatureParameters getParameters(ASiCWithCAdESSignatureParameters parameters) {
		CAdESSignatureParameters cadesParameters = parameters;
		SignatureLevel asicProfile = parameters.getSignatureLevel();
		SignatureLevel underlyingLevel;
		switch (asicProfile) {
			case ASiC_S_BASELINE_B:
			case ASiC_E_BASELINE_B:
			case CAdES_BASELINE_B:
				underlyingLevel = SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_S_BASELINE_T:
			case ASiC_E_BASELINE_T:
			case CAdES_BASELINE_T:
				underlyingLevel = SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_S_BASELINE_LT:
			case ASiC_E_BASELINE_LT:
			case CAdES_BASELINE_LT:
				underlyingLevel = SignatureLevel.CAdES_BASELINE_LT;
				break;
			case ASiC_S_BASELINE_LTA:
			case ASiC_E_BASELINE_LTA:
			case CAdES_BASELINE_LTA:
				underlyingLevel = SignatureLevel.CAdES_BASELINE_LTA;
				break;
			default:
				throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		cadesParameters.setSignatureLevel(underlyingLevel);
		cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return cadesParameters;
	}

	private void buildCAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {
		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		zipWriteBytes(outZip, signature.getBytes());
	}

	private void zipWriteBytes(final ZipOutputStream outZip, final byte[] bytes) throws DSSException {
		try {
			outZip.write(bytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private String getSignatureFileName(final ASiCParameters asicParameters) {
		final boolean asice = isAsice(asicParameters);
		final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();
		if (asice && (enclosedSignature != null)) {
			return META_INF + asicParameters.getSignatureFileName();
		} else {
			return asice ? ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE : ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE;
		}
	}

	private String getSignatureMimeType(final ASiCParameters asicParameters) {
		return MimeType.PKCS7.getMimeTypeString();
	}

	private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip) throws DSSException {
		final byte[] mimeTypeBytes = getMimeTypeBytes(asicParameters).getBytes();
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);

		writeZipEntry(outZip, mimeTypeBytes, entryMimetype);
	}

	private void writeZipEntry(final ZipOutputStream outZip, final byte[] mimeTypeBytes, final ZipEntry entryMimetype) throws DSSException {
		createZipEntry(outZip, entryMimetype);
		zipWriteBytes(outZip, mimeTypeBytes);
	}

	private void storeSignedFiles(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws IOException {

		DSSDocument currentDetachedDocument = detachedDocument;
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
			final ZipEntry entryDocument = new ZipEntry(name);
			outZip.setLevel(ZipEntry.DEFLATED);
			try {

				createZipEntry(outZip, entryDocument);
				final InputStream inputStream = currentDetachedDocument.openStream();
				IOUtils.copy(inputStream, outZip);
				IOUtils.closeQuietly(inputStream);
			} catch (DSSException e) {
				if (!((e.getCause() instanceof ZipException) && e.getCause().getMessage().startsWith("duplicate entry:"))) {
					throw e;
				}
			}
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
	}

	private String getMimeTypeBytes(final ASiCParameters asicParameters) {
		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeBytes;
		if (StringUtils.isBlank(asicParameterMimeType)) {
			if (isAsice(asicParameters)) {
				mimeTypeBytes = MimeType.ASICE.getMimeTypeString();
			} else {
				mimeTypeBytes = MimeType.ASICS.getMimeTypeString();
			}
		} else {
			mimeTypeBytes = asicParameterMimeType;
		}
		return mimeTypeBytes;
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

	private void storeXmlDom(final OutputStream outZip, final Document xml) throws DSSException {
		try {
			final DOMSource xmlSource = new DOMSource(xml);
			final StreamResult outputTarget = new StreamResult(outZip);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private boolean isAsice(final ASiCParameters asicParameters) {
		return SignatureForm.ASiC_E.equals(asicParameters.getContainerForm());
	}

	/**
	 * This method returns the specific service associated with the container: CAdES.
	 *
	 * @param specificParameters {@code DocumentSignatureService}
	 * @return
	 */
	protected CAdESService getCAdESService() {
		if (cadesService == null){
			cadesService = new CAdESService(certificateVerifier);
			cadesService.setTspSource(tspSource);
		}
		return cadesService;
	}
}