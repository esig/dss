/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

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
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCCMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;

/**
 * Implementation of {@code DocumentSignatureService} for ASiC-S and -E containers. It allows the creation of containers based on XAdES or CAdES standard.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";
	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	private final static String ASICS_EXTENSION = ".asics"; // can be ".scs"
	private final static String ASICE_EXTENSION = ".asice"; // can be ".sce"
	private final static String ASICS_NS = "asic:XAdESSignatures";

	/**
	 * This is the constructor to create an instance of the {@code ASiCService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public ASiCService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ ASiCService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureParameters underlyingParameters = getParameters(parameters);

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, underlyingParameters);
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());
		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
		return underlyingService.getDataToSign(contextToSignDocument, underlyingParameters);
	}

	/**
	 * ETSI TS 102 918 v1.2.1 (2012-02) <br />
	 * <p>
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
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		// Signs the toSignDocument first
		SignatureParameters underlyingParameters = getParameters(parameters);

		DSSDocument contextToSignDocument = prepare(toSignDocument, underlyingParameters);
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
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
		final InMemoryDocument asicSignature = buildASiCContainer(contextToSignDocument, asicContainer, underlyingParameters, signature);
		parameters.setDeterministicId(null);
		return asicSignature;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {

			throw new DSSNullException(SignatureTokenConnection.class);
		}
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry privateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
		final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
		final DocumentSignatureService specificService = getSpecificService(parameters);
		specificService.setTspSource(tspSource);

		final SignatureParameters xadesParameters = getParameters(parameters);
		final DSSDocument detachedContent = parameters.getDetachedContent();
		final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, detachedContent);
		xadesParameters.setDetachedContent(detachedContents);
		final DSSDocument signature = subordinatedValidator.getDocument();
		final DSSDocument signedDocument = specificService.extendDocument(signature, xadesParameters);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final ZipOutputStream zip = new ZipOutputStream(output);
		final ZipInputStream input = new ZipInputStream(toExtendDocument.openStream());
		ZipEntry entry;
		while ((entry = getNextZipEntry(input)) != null) {

			final String name = entry.getName();
			final ZipEntry newEntry = new ZipEntry(name);
			if (ASiCContainerValidator.isXAdES(name) || ASiCContainerValidator.isCAdES(name)) {

				createZipEntry(zip, newEntry);
				DSSUtils.copy(signedDocument.openStream(), zip);
			} else {

				createZipEntry(zip, newEntry);
				DSSUtils.copy(input, zip);
			}
		}
		DSSUtils.close(zip);
		return new InMemoryDocument(output.toByteArray());
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

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument signDocument, final SignatureParameters underlyingParameters,
	                                            final DSSDocument signature) {

		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);

		final String toSignDocumentName = toSignDocument.getName();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		ZipOutputStream zipOutputStream = new ZipOutputStream(outBytes);
		if (asice && signDocument != null) {

			copyZipContent(signDocument, zipOutputStream);
		} else {

			storeZipComment(asicParameters, zipOutputStream, toSignDocumentName);

			storeMimetype(asicParameters, zipOutputStream);
		}
		storeSignedFiles(toSignDocument, zipOutputStream);

		storesSignature(asicParameters, signature, zipOutputStream);

		if (asice && cadesForm) {
			storeAsicManifest(underlyingParameters, toSignDocument, zipOutputStream);
		}
		DSSUtils.close(zipOutputStream);

		final InMemoryDocument asicContainer = createASiCContainer(asicParameters, outBytes, toSignDocumentName);
		return asicContainer;
	}

	private void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) {
		final ZipInputStream zipInputStream = new ZipInputStream(toSignAsicContainer.openStream());
		for (ZipEntry entry = getNextZipEntry(zipInputStream); entry != null; entry = getNextZipEntry(zipInputStream)) {

			createZipEntry(zipOutputStream, entry);
			DSSUtils.copy(zipInputStream, zipOutputStream);
		}
		DSSUtils.closeQuietly(zipInputStream);
	}

	private void storeAsicManifest(final SignatureParameters underlyingParameters, final DSSDocument detachedDocument, final ZipOutputStream outZip) {

		final String signatureName = getSignatureFileName(underlyingParameters.aSiC());
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature + "signature".length());
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifest(underlyingParameters, detachedDocument, outZip);
	}

	private void buildAsicManifest(final SignatureParameters underlyingParameters, final DSSDocument detachedDocument, final OutputStream outputStream) {

		final ASiCParameters asicParameters = underlyingParameters.aSiC();

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
			final String base64Encoded = DSSUtils.base64Encode(digest);
			final Text textNode = documentDom.createTextNode(base64Encoded);
			digestValueDom.appendChild(textNode);

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

		storeXmlDom(outputStream, documentDom);
	}

	private static void createZipEntry(final ZipOutputStream outZip, final ZipEntry entrySignature) throws DSSException {

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

		if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {

			outZip.setComment("mimetype=" + getMimeTypeBytes(asicParameters));
		}
	}

	private DSSDocument prepare(final DSSDocument detachedDocument, final SignatureParameters underlyingParameters) {

		// detachedDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = detachedDocument;
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);
		final DocumentValidator validator = getAsicValidator(detachedDocument);
		if (isAsicValidator(validator)) {

			// This is already an existing ASiC container; a new signature should be added.
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DSSDocument contextSignature = subordinatedValidator.getDocument();
			underlyingParameters.aSiC().setEnclosedSignature(contextSignature);
			if (asice) {

				if (cadesForm) {

					final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
					buildAsicManifest(underlyingParameters, underlyingParameters.getDetachedContent(), outputStream);
					contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
					underlyingParameters.setDetachedContent(null);
				} else {
					contextToSignDocument = underlyingParameters.getDetachedContent();
				}
			} else {
				contextToSignDocument = copyDetachedContent(underlyingParameters, subordinatedValidator);
			}
			if (!asice && subordinatedValidator instanceof ASiCCMSDocumentValidator) {

				contextToSignDocument = contextSignature;
			}
		} else {

			if (asice && cadesForm) {

				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				buildAsicManifest(underlyingParameters, detachedDocument, outputStream);
				contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
			} else {
				underlyingParameters.setDetachedContent(contextToSignDocument);
			}
		}
		return contextToSignDocument;
	}

	private boolean isAsicValidator(final DocumentValidator documentValidator) {

		final boolean result = documentValidator != null && (documentValidator instanceof ASiCContainerValidator);
		return result;
	}

	private static ZipEntry getNextZipEntry(final ZipInputStream zipInputStream) throws DSSException {
		try {
			return zipInputStream.getNextEntry();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private DSSDocument getDetachedContents(final DocumentValidator subordinatedValidator, DSSDocument originalDocument) {

		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		if (detachedContents == null || detachedContents.size() == 0) {

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
	private SignatureParameters getParameters(final SignatureParameters parameters) {

		final SignatureParameters underlyingParameters = new SignatureParameters(parameters);
		final SignatureLevel asicProfile = parameters.getSignatureLevel();
		final SignatureForm asicSignatureForm = parameters.aSiC().getUnderlyingForm();
		final SignatureLevel underlyingLevel;
		final boolean xades = asicSignatureForm == SignatureForm.XAdES;
		switch (asicProfile) {

			case ASiC_S_BASELINE_B:
			case ASiC_E_BASELINE_B:
				underlyingLevel = xades ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_S_BASELINE_T:
			case ASiC_E_BASELINE_T:
				underlyingLevel = xades ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_S_BASELINE_LT:
			case ASiC_E_BASELINE_LT:
				underlyingLevel = xades ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
				break;
			case ASiC_S_BASELINE_LTA:
			case ASiC_E_BASELINE_LTA:
				underlyingLevel = xades ? SignatureLevel.XAdES_BASELINE_LTA : SignatureLevel.CAdES_BASELINE_LTA;
				break;
			default:
				throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		underlyingParameters.setSignatureLevel(underlyingLevel);
		underlyingParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return underlyingParameters;
	}

	private void buildCAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {


		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		zipWriteBytes(outZip, signature.getBytes());
	}

	private static void zipWriteBytes(final ZipOutputStream outZip, final byte[] bytes) throws DSSException {

		try {
			outZip.write(bytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private String getSignatureFileName(final ASiCParameters asicParameters) {

		final boolean asice = isAsice(asicParameters);
		final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();
		if (isXAdESForm(asicParameters)) {

			if (asice && enclosedSignature != null) {

				return META_INF + asicParameters.getSignatureFileName();
			} else {

				return asice ? ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE : ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE;
			}
		} else if (isCAdESForm(asicParameters)) {

			if (asice && enclosedSignature != null) {

				return META_INF + asicParameters.getSignatureFileName();
			} else {

				return asice ? ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE : ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE;
			}
		} else {

			throw new DSSException("ASiC signature form must be XAdES or CAdES!");
		}
	}

	private String getSignatureMimeType(final ASiCParameters asicParameters) {

		if (isXAdESForm(asicParameters)) {

			return MimeType.PKCS7.getCode();
		} else if (isCAdESForm(asicParameters)) {

			return MimeType.PKCS7.getCode();
		} else {

			throw new DSSException("ASiC signature form must be XAdES or CAdES!");
		}
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

	private void storeSignedFiles(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws DSSException {

		DSSDocument currentDetachedDocument = detachedDocument;
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
			final ZipEntry entryDocument = new ZipEntry(name);
			outZip.setLevel(ZipEntry.DEFLATED);
			try {

				createZipEntry(outZip, entryDocument);
				DSSUtils.copy(currentDetachedDocument.openStream(), outZip);
			} catch (DSSException e) {
				if (!(e.getCause() instanceof ZipException && e.getCause().getMessage().startsWith("duplicate entry:"))) {
					throw e;
				}
			}
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
	}

	private String getMimeTypeBytes(final ASiCParameters asicParameters) {

		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeBytes;
		if (DSSUtils.isBlank(asicParameterMimeType)) {

			if (isAsice(asicParameters)) {
				mimeTypeBytes = MimeType.ASICE.getCode();
			} else {
				mimeTypeBytes = MimeType.ASICS.getCode();
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

	/**
	 * This method creates a XAdES signature. When adding a new signature,  this one is appended to the already present signatures.
	 *
	 * @param asicParameters already present signatures
	 * @param signature      signature being created
	 * @param outZip         destination {@code ZipOutputStream}
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private void buildXAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		// Creates the XAdES signature
		final Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
		final Element documentElement = xmlSignatureDoc.getDocumentElement();
		final Element xmlSignatureElement = (Element) xmlSignatureDoc.removeChild(documentElement);

		final Document xmlXAdESDoc;
		final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();
		if (enclosedSignature != null && isAsics(asicParameters)) {

			final Document contextXmlSignatureDoc = DSSXMLUtils.buildDOM(enclosedSignature);
			final Element contextDocumentElement = contextXmlSignatureDoc.getDocumentElement();
			contextXmlSignatureDoc.adoptNode(xmlSignatureElement);
			contextDocumentElement.appendChild(xmlSignatureElement);
			xmlXAdESDoc = contextXmlSignatureDoc;
		} else {

			xmlXAdESDoc = DSSXMLUtils.createDocument(ASiCNamespaces.ASiC, ASICS_NS, xmlSignatureElement);
		}
		storeXmlDom(outZip, xmlXAdESDoc);
	}

	private void storeXmlDom(final OutputStream outZip, final Document xml) throws DSSException {

		try {
			final DOMSource xmlSource = new DOMSource(xml);
			final StreamResult outputTarget = new StreamResult(outZip);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
		} catch (TransformerException e) {
			throw new DSSException(e);
		} catch (TransformerFactoryConfigurationError transformerFactoryConfigurationError) {
			transformerFactoryConfigurationError.printStackTrace();
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
	 * @param specificParameters {@code DocumentSignatureService}
	 * @return
	 */
	protected DocumentSignatureService getSpecificService(final SignatureParameters specificParameters) {

		final SignatureForm asicSignatureForm = specificParameters.aSiC().getUnderlyingForm();
		final DocumentSignatureService underlyingASiCService = specificParameters.getContext().getUnderlyingASiCService(certificateVerifier, asicSignatureForm);
		underlyingASiCService.setTspSource(tspSource);
		return underlyingASiCService;
	}
}