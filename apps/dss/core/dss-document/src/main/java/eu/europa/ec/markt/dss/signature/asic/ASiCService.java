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
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
	private final static String ZIP_ENTRY_METAINF_XADES_SIGNATURE = "META-INF/signatures.xml";
	private final static String ZIP_ENTRY_METAINF_CADES_SIGNATURE = "META-INF/signature.p7s";

	private final static String ASICS_EXTENSION = ".asics"; // can be ".scs"
	private final static String ASICE_EXTENSION = ".asice"; // can be ".sce"
	private final static String ASICS_NS = "asic:XAdESSignatures";
	private final static String ASICS_URI = "http://uri.etsi.org/02918/v1.2.1#";

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
		parameters.aSiC().setEnclosedSignature(underlyingParameters.aSiC().getEnclosedSignature());
		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
		return underlyingService.getDataToSign(contextToSignDocument, underlyingParameters);
	}

	private DSSDocument copyDetachedContent(final SignatureParameters specificParameters, final DocumentValidator subordinatedValidator) {

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
		specificParameters.setDetachedContent(contextToSignDocument);
		return contextToSignDocument;
	}

	private DocumentValidator getValidator(final DSSDocument toSignDocument) {

		DocumentValidator validator = null;
		// Check if this is an existing container
		try {
			validator = SignedDocumentValidator.fromDocument(toSignDocument);
		} catch (Exception e) {
			// do nothing
		}
		return validator;
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
		final SignatureParameters underlyingParameters = getParameters(parameters);

		final DSSDocument contextToSignDocument = prepare(toSignDocument, underlyingParameters);
		parameters.aSiC().setEnclosedSignature(underlyingParameters.aSiC().getEnclosedSignature());

		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
		final DSSDocument signature = underlyingService.signDocument(contextToSignDocument, underlyingParameters, signatureValue);

		final InMemoryDocument asicSignature = buildASiCContainer(underlyingParameters, signature);
		parameters.setDeterministicId(null);
		return asicSignature;
	}

	private InMemoryDocument buildASiCContainer(final SignatureParameters underlyingParameters, final DSSDocument signature) {

		final DSSDocument detachedDocument = underlyingParameters.getDetachedContent();

		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();
		final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		final ZipOutputStream outZip = new ZipOutputStream(outBytes);

		final MimeType signedFileMimeType = detachedDocument.getMimeType();

		final String toSignDocumentName = detachedDocument.getName();

		// Zip comment
		storeZipComment(asicParameters, outZip, toSignDocumentName, signedFileMimeType);

		// Stores the ASiC mime-type
		storeMimetype(asicParameters, outZip, signedFileMimeType);

		// Stores the original toSignDocument
		storeSignedFile(detachedDocument, outZip);

		// Stores the signature
		storesSignature(signature, enclosedSignature, underlyingForm, outZip);

		// Finishes the ZIP (with implicit finish/flush)
		DSSUtils.close(outZip);

		// return the new toSignDocument = ASiC-S
		final InMemoryDocument asicContainer = createASiCContainer(asicParameters, outBytes, toSignDocumentName);
		return asicContainer;
	}

	private InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream outBytes, final String toSignDocumentName) {

		final byte[] documentBytes = outBytes.toByteArray();
		final SignatureForm containerForm = asicParameters.getContainerForm();
		final String extension = SignatureForm.ASiC_S.equals(containerForm) ? ASICS_EXTENSION : ASICE_EXTENSION;
		final String name = toSignDocumentName != null ? toSignDocumentName + extension : null;
		final MimeType mimeType = SignatureForm.ASiC_S.equals(containerForm) ? MimeType.ASICS : MimeType.ASICE;
		return new InMemoryDocument(documentBytes, name, mimeType);
	}

	private void storesSignature(final DSSDocument signature, final DSSDocument enclosedSignature, final SignatureForm asicSignatureForm, final ZipOutputStream outZip) {

		if (SignatureForm.XAdES.equals(asicSignatureForm)) {

			buildXAdES(enclosedSignature, signature, outZip);
		} else if (SignatureForm.CAdES.equals(asicSignatureForm)) {

			buildCAdES(signature, outZip);
		}
	}

	private void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream outZip, final String toSignDocumentName, final MimeType signedFileMimeType) {

		if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {

			outZip.setComment("mimetype=" + signedFileMimeType.getCode());
		}
	}

	private DSSDocument prepare(final DSSDocument toSignDocument, final SignatureParameters underlyingParameters) {

		// toSignDocument can be a simple file or an ASiC container
		DSSDocument contextToSignDocument = toSignDocument;
		final DocumentValidator validator = getValidator(toSignDocument);
		underlyingParameters.setDetachedContent(contextToSignDocument);
		if (isAsicValidator(validator)) {

			// This is already an existing ASiC container; a new signature should be added.
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			contextToSignDocument = copyDetachedContent(underlyingParameters, subordinatedValidator);
			final DSSDocument contextSignature = subordinatedValidator.getDocument();
			underlyingParameters.aSiC().setEnclosedSignature(contextSignature);
			if (subordinatedValidator instanceof ASiCCMSDocumentValidator) {

				contextToSignDocument = contextSignature;
			}
		}
		return contextToSignDocument;
	}

	private boolean isAsicValidator(final DocumentValidator asicValidator) {

		final boolean result = asicValidator != null && (asicValidator instanceof ASiCContainerValidator);
		return result;
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

		try {

			final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DSSDocument signature = subordinatedValidator.getDocument();
			DSSDocument originalDocument = parameters.getDetachedContent();
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
			final DocumentSignatureService specificService = getSpecificService(parameters);
			specificService.setTspSource(tspSource);

			final SignatureParameters xadesParameters = getParameters(parameters);
			xadesParameters.setDetachedContent(originalDocument);
			final DSSDocument signedDocument = specificService.extendDocument(signature, xadesParameters);

			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final ZipOutputStream zip = new ZipOutputStream(output);

			final ZipInputStream input = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry;
			while ((entry = input.getNextEntry()) != null) {

				ZipEntry newEntry = new ZipEntry(entry.getName());
				if (ZIP_ENTRY_METAINF_XADES_SIGNATURE.equals(entry.getName())) {

					zip.putNextEntry(newEntry);
					DSSUtils.copy(signedDocument.openStream(), zip);
				} else {

					zip.putNextEntry(newEntry);
					DSSUtils.copy(input, zip);
				}
			}
			zip.close();
			return new InMemoryDocument(output.toByteArray());
		} catch (IOException e) {

			throw new DSSException(e);
		}
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

	private void buildCAdES(final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_CADES_SIGNATURE);
		try {
			outZip.putNextEntry(entrySignature);
			final byte[] bytes = signature.getBytes();
			outZip.write(bytes);
			//DSSUtils.copy(signature.openStream(), outZip);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip, final MimeType containedFileMimeType) throws DSSException {

		final byte[] mimeTypeBytes = getMimeTypeBytes(asicParameters, containedFileMimeType);
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);

		writeZipEntry(outZip, mimeTypeBytes, entryMimetype);
	}

	private void writeZipEntry(final ZipOutputStream outZip, final byte[] mimeTypeBytes, final ZipEntry entryMimetype) throws DSSException {

		try {
			outZip.putNextEntry(entryMimetype);
			outZip.write(mimeTypeBytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void storeSignedFile(final DSSDocument toSignDocument, final ZipOutputStream outZip) throws DSSException {

		DSSDocument currentToSignDocument = toSignDocument;
		do {

			final String toSignDocumentName = currentToSignDocument.getName();
			final ZipEntry entryDocument = new ZipEntry(toSignDocumentName != null ? toSignDocumentName : ZIP_ENTRY_DETACHED_FILE);
			outZip.setLevel(ZipEntry.DEFLATED);

			try {
				outZip.putNextEntry(entryDocument);
				DSSUtils.copy(currentToSignDocument.openStream(), outZip);
			} catch (IOException e) {
				throw new DSSException(e);
			}
			currentToSignDocument = currentToSignDocument.getNextDocument();
		} while (currentToSignDocument != null);
	}

	private byte[] getMimeTypeBytes(final ASiCParameters asicParameters, final MimeType containedFileMimeType) {

		final byte[] mimeTypeBytes;
		final String asicParameterMimeType = asicParameters.getMimeType();
		if (DSSUtils.isBlank(asicParameterMimeType)) {
			mimeTypeBytes = containedFileMimeType.getCode().getBytes();
		} else {
			mimeTypeBytes = asicParameterMimeType.getBytes();
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
	 * @param contextSignature already present signatures
	 * @param signature        signature being created
	 * @param outZip           destination {@code ZipOutputStream}
	 * @throws IOException
	 * @throws TransformerException
	 */
	private void buildXAdES(final DSSDocument contextSignature, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		try {

			final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_XADES_SIGNATURE);
			outZip.putNextEntry(entrySignature);
			// Creates the XAdES signature
			final Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
			final Element documentElement = xmlSignatureDoc.getDocumentElement();
			final Element xmlSignatureElement = (Element) xmlSignatureDoc.removeChild(documentElement);

			final Document xmlXAdESDoc;
			if (contextSignature != null) {

				final Document contextXmlSignatureDoc = DSSXMLUtils.buildDOM(contextSignature);
				final Element contextDocumentElement = contextXmlSignatureDoc.getDocumentElement();
				contextXmlSignatureDoc.adoptNode(xmlSignatureElement);
				contextDocumentElement.appendChild(xmlSignatureElement);
				xmlXAdESDoc = contextXmlSignatureDoc;
			} else {

				xmlXAdESDoc = DSSXMLUtils.createDocument(ASICS_URI, ASICS_NS, xmlSignatureElement);
			}
			TransformerFactory.newInstance().newTransformer().transform(new DOMSource(xmlXAdESDoc), new StreamResult(outZip));
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (TransformerException e) {
			throw new DSSException(e);
		}
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