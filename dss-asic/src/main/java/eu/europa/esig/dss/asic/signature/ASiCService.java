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
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.ASiCNamespaces;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * Implementation of {@code DocumentSignatureService} for ASiC-S and -E containers. It allows the creation of containers
 * based on XAdES or CAdES standard.
 *
 */
public class ASiCService extends AbstractSignatureService<ASiCSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";
	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	public final static String ASICS_NS = "asic:XAdESSignatures";

	/**
	 * This is the constructor to create an instance of the {@code ASiCService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public ASiCService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ ASiCService created");
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final ASiCSignatureParameters parameters) throws DSSException {
		try {
			if (!canBeSigned(toSignDocument, parameters)) { // First verify if the file can be signed
				throw new DSSUnsupportedOperationException("You can only sign an ASiC container by using the same type of container and of signature");
			}
		} catch (IOException e) {
			throw new DSSException(e);
		}

		final ASiCParameters asicParameters = parameters.aSiC();

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		final AbstractSignatureParameters underlyingParameters = getParameters(parameters);
		if (isAsice(asicParameters) && isCAdESForm(asicParameters)) {
			underlyingParameters.setDetachedContent(null);
		}
		final DocumentSignatureService underlyingService = getSpecificService(parameters.aSiC().getUnderlyingForm());
		return underlyingService.getDataToSign(contextToSignDocument, underlyingParameters);
	}

	/**
	 * ETSI TS 102 918 v1.2.1 (2012-02) <br />
	 *
	 * Contents of Container ( 6.2.2 )
	 * </p>
	 * <ul>
	 * <li>The file extension ".asics" should be used .</li>
	 * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in
	 * clause
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
	public DSSDocument signDocument(final DSSDocument toSignDocument, final ASiCSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {
		try {

			if (!canBeSigned(toSignDocument, parameters)) {
				throw new DSSUnsupportedOperationException("You can only sign an ASiC container by using the same type of container and of signature");
			}
			assertSigningDateInCertificateValidityRange(parameters);

			// Signs the toSignDocument first
			final ASiCParameters asicParameters = parameters.aSiC();

			DSSDocument contextToSignDocument = prepare(toSignDocument, parameters);
			parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

			AbstractSignatureParameters underlyingParameters = getParameters(parameters);
			if (isAsice(asicParameters) && isCAdESForm(asicParameters)) {
				underlyingParameters.setDetachedContent(null);
			}
			final DocumentSignatureService underlyingService = getSpecificService(parameters.aSiC().getUnderlyingForm());
			final DSSDocument signature = underlyingService.signDocument(contextToSignDocument, underlyingParameters, signatureValue);

			underlyingParameters = getParameters(parameters);
			DSSDocument asicContainer = null;
			final boolean signingContainer = asicParameters.getEnclosedSignature() != null;
			if (signingContainer) {
				asicContainer = toSignDocument;
			}
			if (isAsice(asicParameters) && isCAdESForm(asicParameters)) {
				if (!signingContainer) {
					contextToSignDocument = toSignDocument;
				} else {
					contextToSignDocument = parameters.getDetachedContent();
				}
			}
			final InMemoryDocument asicSignature = buildASiCContainer(contextToSignDocument, asicContainer, parameters, signature);
			asicSignature.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
			parameters.reinitDeterministicId();
			return asicSignature;

		} catch (IOException e) {
			throw new DSSException(e);
		}

	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final ASiCSignatureParameters parameters) throws DSSException {
		try {
			final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DocumentSignatureService specificService = getSpecificService(parameters.aSiC().getUnderlyingForm());
			specificService.setTspSource(tspSource);

			final AbstractSignatureParameters underlyingParameters = getParameters(parameters);
			final DSSDocument detachedContent = parameters.getDetachedContent();
			final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, detachedContent);
			underlyingParameters.setDetachedContent(detachedContents);
			final DSSDocument signature = subordinatedValidator.getDocument();
			final DSSDocument signedDocument = specificService.extendDocument(signature, underlyingParameters);

			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final ZipOutputStream zipOutputStream = new ZipOutputStream(output);
			final ZipInputStream zipInputStream = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry;
			while ((entry = getNextZipEntry(zipInputStream)) != null) {

				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (ASiCUtils.isMimetype(name)) {

					storeMimetype(parameters.aSiC(), zipOutputStream);
				} else if (ASiCUtils.isXAdES(name) || ASiCUtils.isCAdES(name)) {

					createZipEntry(zipOutputStream, newEntry);
					final InputStream inputStream = signedDocument.openStream();
					Utils.copy(inputStream, zipOutputStream);
					Utils.closeQuietly(inputStream);
				} else {

					createZipEntry(zipOutputStream, newEntry);
					Utils.copy(zipInputStream, zipOutputStream);
				}
			}
			Utils.closeQuietly(zipInputStream);
			Utils.closeQuietly(zipOutputStream);
			DSSDocument asicSignature = new InMemoryDocument(output.toByteArray(), null, getMimeType(parameters.aSiC().getContainerForm()));
			asicSignature.setName(DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
			return asicSignature;
		} catch (IOException e) {
			throw new DSSException(e);
		}
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

	private DocumentValidator getAsicValidator(final DSSDocument toSignDocument) {
		if (ASiCUtils.isASiCContainer(toSignDocument)) {
			return SignedDocumentValidator.fromDocument(toSignDocument);
		}
		return null;
	}

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument signDocument, final ASiCSignatureParameters parameters,
			final DSSDocument signature) throws IOException {

		ASiCParameters asicParameters = parameters.aSiC();

		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);
		final boolean xadesForm = isXAdESForm(asicParameters);

		final String toSignDocumentName = toSignDocument.getName();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		ZipOutputStream zipOutputStream = new ZipOutputStream(outBytes);
		if (asice && (signDocument != null)) {

			copyZipContent(signDocument, zipOutputStream);
		} else {
			if (signDocument != null && isCAdESForm(asicParameters)) {
				copyMETAINFContent(signDocument, zipOutputStream);
			}
			storeZipComment(asicParameters, zipOutputStream, toSignDocumentName);

			storeMimetype(asicParameters, zipOutputStream);
		}
		storeSignedFiles(toSignDocument, zipOutputStream);

		storesSignature(asicParameters, signature, zipOutputStream);

		if (asice) {
			if (cadesForm) {
				storeAsicManifestCAdES(parameters, toSignDocument, zipOutputStream);
			} else if (signDocument == null && xadesForm) { // only one manifest file / zip
				storeManifestXAdES(parameters, toSignDocument, zipOutputStream);
			}
		}
		Utils.closeQuietly(zipOutputStream);

		final InMemoryDocument asicContainer = createASiCContainer(asicParameters, outBytes);
		return asicContainer;
	}

	private void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) throws IOException {

		final InputStream inputStream = toSignAsicContainer.openStream();
		final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		for (ZipEntry entry = getNextZipEntry(zipInputStream); entry != null; entry = getNextZipEntry(zipInputStream)) {

			createZipEntry(zipOutputStream, entry);
			Utils.copy(zipInputStream, zipOutputStream);
		}
		Utils.closeQuietly(zipInputStream);
	}

	private void copyMETAINFContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) throws IOException {
		final InputStream inputStream = toSignAsicContainer.openStream();
		final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		for (ZipEntry entry = getNextZipEntry(zipInputStream); entry != null; entry = getNextZipEntry(zipInputStream)) {
			if (entry.getName().contains("META-INF/")) {
				createZipEntry(zipOutputStream, entry);
				Utils.copy(zipInputStream, zipOutputStream);
			}
		}
		Utils.closeQuietly(zipInputStream);
	}

	private void storeAsicManifestCAdES(ASiCSignatureParameters parameters, final DSSDocument detachedDocument, final ZipOutputStream outZip) {

		ASiCParameters asicParameters = parameters.aSiC();

		final String signatureName = getSignatureFileName(asicParameters);
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature);
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifestCAdES(parameters, detachedDocument, outZip);
	}

	private void buildAsicManifestCAdES(final ASiCSignatureParameters underlyingParameters, final DSSDocument detachedDocument,
			final OutputStream outputStream) {

		ASiCParameters asicParameters = underlyingParameters.aSiC();

		final Document documentDom = DSSXMLUtils.buildDOM();
		final Element asicManifestDom = documentDom.createElementNS(ASiCNamespaces.ASiC, "asic:ASiCManifest");
		documentDom.appendChild(asicManifestDom);

		final Element sigReferenceDom = DSSXMLUtils.addElement(documentDom, asicManifestDom, ASiCNamespaces.ASiC, "asic:SigReference");
		final String signatureName = getSignatureFileName(asicParameters);
		sigReferenceDom.setAttribute("URI", signatureName);
		sigReferenceDom.setAttribute("MimeType", MimeType.PKCS7.getMimeTypeString()); // only CAdES form

		DSSDocument currentDetachedDocument = detachedDocument;
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final Element dataObjectReferenceDom = DSSXMLUtils.addElement(documentDom, sigReferenceDom, ASiCNamespaces.ASiC, "asic:DataObjectReference");
			dataObjectReferenceDom.setAttribute("URI", detachedDocumentName);

			final Element digestMethodDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
			final DigestAlgorithm digestAlgorithm = underlyingParameters.getDigestAlgorithm();
			digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

			final Element digestValueDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
			final byte[] digest = DSSUtils.digest(digestAlgorithm, currentDetachedDocument);
			final String base64Encoded = Utils.toBase64(digest);
			final Text textNode = documentDom.createTextNode(base64Encoded);
			digestValueDom.appendChild(textNode);

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

		storeXmlDom(outputStream, documentDom);
	}

	private void storeManifestXAdES(ASiCSignatureParameters parameters, final DSSDocument detachedDocument, final ZipOutputStream outZip) {
		final String asicManifestZipEntryName = META_INF + "manifest.xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifestXAdES(parameters, detachedDocument, outZip);
	}

	// <?xml version="1.0" encoding="UTF-8" standalone="no" ?>
	// <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">>
	// <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
	// <manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
	// <manifest:file-entry manifest:full-path="test-data-file.bin" manifest:media-type="application/octet-stream"/>
	// </manifest:manifest>
	private void buildAsicManifestXAdES(ASiCSignatureParameters parameters, DSSDocument detachedDocument, OutputStream outputStream) {
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

	private void createZipEntry(final ZipOutputStream outZip, final ZipEntry entrySignature) throws DSSException {
		try {
			outZip.putNextEntry(entrySignature);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream outBytes) {
		SignatureForm containerForm = asicParameters.getContainerForm();
		return new InMemoryDocument(outBytes.toByteArray(), null, getMimeType(containerForm));
	}

	private MimeType getMimeType(SignatureForm containerForm) {
		boolean asics = SignatureForm.ASiC_S.equals(containerForm);
		return asics ? MimeType.ASICS : MimeType.ASICE;
	}

	private void storesSignature(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) {
		if (isXAdESForm(asicParameters)) {
			buildXAdES(asicParameters, signature, outZip);
		} else if (isCAdESForm(asicParameters)) {
			buildCAdES(asicParameters, signature, outZip);
		} else {
			throw new DSSException("ASiC signature form must be XAdES or CAdES!");
		}
	}

	private boolean isCAdESForm(final ASiCParameters asicParameters) {
		final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();
		return SignatureForm.CAdES.equals(underlyingForm);
	}

	private boolean isXAdESForm(final ASiCParameters asicParameters) {
		final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();
		return SignatureForm.XAdES.equals(underlyingForm);
	}

	private void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream outZip, final String toSignDocumentName) {
		if (asicParameters.isZipComment() && Utils.isStringNotEmpty(toSignDocumentName)) {
			outZip.setComment("mimetype=" + getMimeTypeBytes(asicParameters));
		}
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final ASiCSignatureParameters underlyingParameter) {

		// detachedDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = detachedDocument;
		ASiCParameters asicParameters = underlyingParameter.aSiC();
		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);
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
				if (cadesForm) {
					final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
					buildAsicManifestCAdES(underlyingParameter, underlyingParameter.getDetachedContent(), outputStream);
					contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
					// underlyingParameter.setDetachedContent(null);
				} else {
					contextToSignDocument = underlyingParameter.getDetachedContent();
				}
			} else {
				contextToSignDocument = copyDetachedContent(underlyingParameter, subordinatedValidator);
			}
			/*
			 * if (!asice && (subordinatedValidator instanceof ASiCCMSDocumentValidator)) {
			 * contextToSignDocument = contextSignature;
			 * }
			 */
		} else {
			if (asice && cadesForm) {
				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				buildAsicManifestCAdES(underlyingParameter, detachedDocument, outputStream);
				contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
			} else {
				underlyingParameter.setDetachedContent(contextToSignDocument);
			}
		}
		return contextToSignDocument;
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

	/**
	 * Creates a specific XAdES/CAdES signature parameters on the base of the provided parameters. Forces the signature
	 * packaging to
	 * DETACHED
	 *
	 * @param parameters
	 *            must provide signingToken, PrivateKeyEntry and date
	 * @return new specific instance for XAdES or CAdES
	 */
	private AbstractSignatureParameters getParameters(final ASiCSignatureParameters parameters) {
		SignatureForm asicSignatureForm = parameters.aSiC().getUnderlyingForm();
		if (SignatureForm.CAdES == asicSignatureForm) {
			return initCAdESSignatureParameters(parameters);
		} else if (SignatureForm.XAdES == asicSignatureForm) {
			return initXAdESSignatureParameters(parameters);
		} else {
			throw new DSSException("Unsupported form : " + asicSignatureForm);
		}
	}

	private XAdESSignatureParameters initXAdESSignatureParameters(ASiCSignatureParameters parameters) {
		XAdESSignatureParameters xadesParameters = new XAdESSignatureParameters();
		initCommonFields(parameters, xadesParameters);
		initXAdESDocumentRoot(xadesParameters, parameters.aSiC());
		SignatureLevel asicProfile = parameters.getSignatureLevel();
		SignatureLevel underlyingLevel;
		switch (asicProfile) {
		case ASiC_S_BASELINE_B:
		case ASiC_E_BASELINE_B:
			underlyingLevel = SignatureLevel.XAdES_BASELINE_B;
			break;
		case ASiC_S_BASELINE_T:
		case ASiC_E_BASELINE_T:
			underlyingLevel = SignatureLevel.XAdES_BASELINE_T;
			break;
		case ASiC_S_BASELINE_LT:
		case ASiC_E_BASELINE_LT:
			underlyingLevel = SignatureLevel.XAdES_BASELINE_LT;
			break;
		case ASiC_S_BASELINE_LTA:
		case ASiC_E_BASELINE_LTA:
			underlyingLevel = SignatureLevel.XAdES_BASELINE_LTA;
			break;
		default:
			throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		xadesParameters.setSignatureLevel(underlyingLevel);
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		xadesParameters.setSignedInfoCanonicalizationMethod(parameters.getSignedInfoCanonicalizationMethod());
		xadesParameters.setSignedPropertiesCanonicalizationMethod(parameters.getSignedPropertiesCanonicalizationMethod());
		return xadesParameters;
	}

	private CAdESSignatureParameters initCAdESSignatureParameters(ASiCSignatureParameters parameters) {
		CAdESSignatureParameters cadesParameters = new CAdESSignatureParameters();
		initCommonFields(parameters, cadesParameters);
		SignatureLevel asicProfile = parameters.getSignatureLevel();
		SignatureLevel underlyingLevel;
		switch (asicProfile) {
		case ASiC_S_BASELINE_B:
		case ASiC_E_BASELINE_B:
			underlyingLevel = SignatureLevel.CAdES_BASELINE_B;
			break;
		case ASiC_S_BASELINE_T:
		case ASiC_E_BASELINE_T:
			underlyingLevel = SignatureLevel.CAdES_BASELINE_T;
			break;
		case ASiC_S_BASELINE_LT:
		case ASiC_E_BASELINE_LT:
			underlyingLevel = SignatureLevel.CAdES_BASELINE_LT;
			break;
		case ASiC_S_BASELINE_LTA:
		case ASiC_E_BASELINE_LTA:
			underlyingLevel = SignatureLevel.CAdES_BASELINE_LTA;
			break;
		default:
			throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		cadesParameters.setSignatureLevel(underlyingLevel);
		cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return cadesParameters;
	}

	private void initCommonFields(AbstractSignatureParameters originalParameters, AbstractSignatureParameters parameters) {
		if (originalParameters.getSigningCertificate() != null) { // extends no need certificate
			parameters.setSigningCertificate(originalParameters.getSigningCertificate());
			parameters.setCertificateChain(originalParameters.getCertificateChain());
		}
		parameters.setSignWithExpiredCertificate(originalParameters.isSignWithExpiredCertificate());
		parameters.setDetachedContent(originalParameters.getDetachedContent());
		parameters.setBLevelParams(originalParameters.bLevel());
		parameters.setDigestAlgorithm(originalParameters.getDigestAlgorithm());
		parameters.setEncryptionAlgorithm(originalParameters.getEncryptionAlgorithm());
		parameters.setContentTimestampParameters(originalParameters.getContentTimestampParameters());
		parameters.setContentTimestamps(originalParameters.getContentTimestamps());
		parameters.setSignatureTimestampParameters(originalParameters.getSignatureTimestampParameters());
		parameters.setArchiveTimestampParameters(originalParameters.getArchiveTimestampParameters());
	}

	private void buildCAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {
		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		zipWriteBytes(outZip, signature);
	}

	private void zipWriteBytes(final ZipOutputStream outZip, final DSSDocument document) throws DSSException {
		try {
			document.writeTo(outZip);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void zipWriteBytes(final ZipOutputStream outZip, final byte[] bytes) throws DSSException {
		try {
			outZip.write(bytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private String getSignatureFileName(final ASiCParameters asicParameters) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return META_INF + asicParameters.getSignatureFileName();
		}
		final boolean asice = isAsice(asicParameters);
		if (isXAdESForm(asicParameters)) {
			if (asice) {
				if (asicParameters.getEnclosedSignature() != null) {
					return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE.replace('1', getSignatureNumber(asicParameters.getEnclosedSignature()));
				} else {
					return ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE;
				}
			} else {
				return ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE;
			}
		} else if (isCAdESForm(asicParameters)) {
			if (asice || asicParameters.getEnclosedSignature() != null) {
				if (asicParameters.getEnclosedSignature() != null) {
					return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE.replace('1', getSignatureNumber(asicParameters.getEnclosedSignature()));
				} else {
					return ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE;
				}
			} else {
				return ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE;
			}
		} else {
			throw new DSSException("ASiC signature form must be XAdES or CAdES!");
		}
	}

	private char getSignatureNumber(DSSDocument enclosedSignature) {
		int signatureNumbre = '1';
		while (enclosedSignature != null) {
			signatureNumbre++;
			enclosedSignature = enclosedSignature.getNextDocument();
		}
		return (char) signatureNumbre;
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
				Utils.copy(inputStream, outZip);
				Utils.closeQuietly(inputStream);
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
		if (Utils.isStringBlank(asicParameterMimeType)) {

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

	private void initXAdESDocumentRoot(XAdESSignatureParameters xadesParameters, ASiCParameters asicParameters) {
		DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();
		Document rootDocument;
		if ((enclosedSignature != null) && isAsics(asicParameters)) {
			rootDocument = DSSXMLUtils.buildDOM(enclosedSignature);
		} else {
			rootDocument = DSSXMLUtils.createDocument(ASiCNamespaces.ASiC, ASICS_NS);
		}
		xadesParameters.setRootDocument(rootDocument);
	}

	/**
	 * This method creates a XAdES signature. When adding a new signature, this one is appended to the already present
	 * signatures.
	 *
	 * @param asicParameters
	 *            ASiC parameters
	 * @param signature
	 *            signature being created
	 * @param outZip
	 *            destination {@code ZipOutputStream}
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private void buildXAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {
		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
		storeXmlDom(outZip, xmlSignatureDoc);
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

	private boolean isAsics(final ASiCParameters asicParameters) {
		return SignatureForm.ASiC_S.equals(asicParameters.getContainerForm());
	}

	private boolean isAsice(final ASiCParameters asicParameters) {
		return SignatureForm.ASiC_E.equals(asicParameters.getContainerForm());
	}

	/**
	 * This method returns the specific service associated with the container: XAdES or CAdES.
	 *
	 * @param specificParameters
	 *            {@code DocumentSignatureService}
	 * @return
	 */
	protected DocumentSignatureService getSpecificService(SignatureForm signatureForm) {
		DocumentSignatureService underlyingASiCService;
		if (signatureForm == SignatureForm.XAdES) {
			underlyingASiCService = new XAdESService(certificateVerifier);
		} else if (signatureForm == SignatureForm.CAdES) {
			underlyingASiCService = new CAdESService(certificateVerifier);
		} else {
			throw new DSSException("Unsupported parameter value: only XAdES and CAdES forms are acceptable!");
		}
		underlyingASiCService.setTspSource(tspSource);
		return underlyingASiCService;
	}

	private boolean canBeSigned(DSSDocument toSignDocument, ASiCSignatureParameters parameters) throws IOException {
		boolean isMimetypeCorrect = true;
		boolean isSignatureTypeCorrect = true;
		if (isArchive(toSignDocument)) {
			isMimetypeCorrect = toSignDocument.getMimeType().getMimeTypeString().equals(getMimeTypeBytes(parameters.aSiC()));
			InputStream stream = toSignDocument.openStream();
			ZipInputStream zip = new ZipInputStream(stream);
			ZipEntry entry = zip.getNextEntry();
			while (entry != null) {
				if (entry.getName().startsWith("META-INF") && entry.getName().contains("signature") && !entry.getName().contains("Manifest")) {
					if (isCAdESForm(parameters.aSiC())) {
						isSignatureTypeCorrect = (entry.getName().endsWith(".p7m") || entry.getName().endsWith(".p7s"));
					} else {
						isSignatureTypeCorrect = entry.getName().endsWith(".xml");
					}
				}
				entry = zip.getNextEntry();
			}
			zip.close();
		}
		return (isMimetypeCorrect && isSignatureTypeCorrect);
	}

	private boolean isArchive(DSSDocument doc) {
		return (doc.getName().endsWith(".zip") || doc.getName().endsWith(".bdoc") || doc.getName().endsWith(".asice") || doc.getName().endsWith(".asics"));
	}
}
