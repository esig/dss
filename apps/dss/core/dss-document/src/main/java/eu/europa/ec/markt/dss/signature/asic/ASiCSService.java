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
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
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
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCCMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;

/**
 * Implementation of DocumentSignatureService for ASiC-S documents. It allows the creation of an ASiC-S container based on XAdES or CAdES standard.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCSService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCSService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String ZIP_ENTRY_METAINF_XADES_SIGNATURE = "META-INF/signatures.xml";
	private final static String ZIP_ENTRY_METAINF_CADES_SIGNATURE = "META-INF/signature.p7s";

	private final static String ASICS_EXTENSION = ".asics";
	private final static String ASICS_NS = "asic:XAdESSignatures";
	private final static String ASICS_URI = "http://uri.etsi.org/2918/v1.2.1#";

	/**
	 * This is the constructor to create an instance of the {@code ASiCSService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public ASiCSService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ ASiCSService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureParameters specificParameters = getParameters(parameters);

		// toSignDocument can be a simple file or an ASiC-S container
		DSSDocument contextToSignDocument = toSignDocument;
		SignedDocumentValidator validator = null;
		try {
			validator = SignedDocumentValidator.fromDocument(toSignDocument);
		} catch (Exception e) {
			// do nothing
		}
		specificParameters.setDetachedContent(contextToSignDocument);
		if (validator != null && (validator instanceof ASiCCMSDocumentValidator || validator instanceof ASiCXMLDocumentValidator)) {

			// This is already an existing ASiC-S container; a new signature should be added.
			// TODO (22/08/2014): This is a List now!
			contextToSignDocument = validator.getDetachedContents().get(0);
			specificParameters.setDetachedContent(contextToSignDocument);
			final DSSDocument contextSignature = validator.getDocument();
			parameters.aSiC().setEnclosedSignature(contextSignature);
			if (validator instanceof ASiCCMSDocumentValidator) {

				contextToSignDocument = contextSignature;
			}
		}
		final DocumentSignatureService underlyingService = getSpecificService(specificParameters);
		return underlyingService.getDataToSign(contextToSignDocument, specificParameters);
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
		final SignatureParameters specificParameters = getParameters(parameters);
		// toSignDocument can be a simple file or an ASiC-S container
		DSSDocument contextToSignDocument = toSignDocument;
		SignedDocumentValidator validator = null;
		try {
			validator = SignedDocumentValidator.fromDocument(toSignDocument);
		} catch (Exception e) {
			// do nothing
		}
		specificParameters.setDetachedContent(contextToSignDocument);
		if (validator != null && (validator instanceof ASiCCMSDocumentValidator || validator instanceof ASiCXMLDocumentValidator)) {

			// This is already an existing ASiC-S container; a new signature should be added.
			// TODO (22/08/2014): This is a List now!
			contextToSignDocument = validator.getDetachedContents().get(0);
			specificParameters.setDetachedContent(contextToSignDocument);
			final DSSDocument contextSignature = validator.getDocument();
			parameters.aSiC().setEnclosedSignature(contextSignature);
			if (validator instanceof ASiCCMSDocumentValidator) {

				contextToSignDocument = contextSignature;
			}
		}

		final ASiCParameters asicParameters = specificParameters.aSiC();

		final DocumentSignatureService underlyingService = getSpecificService(specificParameters);

		final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();

		final SignatureForm asicSignatureForm = asicParameters.getAsicSignatureForm();
		final DSSDocument signature;
		if (SignatureForm.XAdES.equals(asicSignatureForm)) {

			signature = underlyingService.signDocument(contextToSignDocument, specificParameters, signatureValue);
		} else if (SignatureForm.CAdES.equals(asicSignatureForm)) {

			signature = underlyingService.signDocument(contextToSignDocument, specificParameters, signatureValue);
		} else {
			throw new DSSUnsupportedOperationException(asicSignatureForm.name() + ": This form of the signature is not supported.");
		}

		final DSSDocument originalDocument = specificParameters.getDetachedContent();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		final ZipOutputStream outZip = new ZipOutputStream(outBytes);

		final String toSignDocumentName = originalDocument.getName();

		//		if (!System.getProperties().containsKey("content.types.user.table")) {
		//			final URL contentTypeURL = this.getClass().getResource("/custom-content-types.properties");
		//			if (contentTypeURL != null) {
		//				System.setProperty("content.types.user.table", contentTypeURL.getPath());
		//			}
		//		}
		//		final FileNameMap fileNameMap = URLConnection.getFileNameMap();
		//		final String containedFileMimeType_ = fileNameMap.getContentTypeFor(toSignDocumentName);
		//		System.out.println(toSignDocument.toString());
		final MimeType signedFileMimeType = originalDocument.getMimeType();
		// Zip comment
		if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {

			outZip.setComment("mimetype=" + signedFileMimeType.getCode());
		}

		// Stores the ASiC mime-type
		storeMimetype(asicParameters, outZip, signedFileMimeType);

		// Stores the original toSignDocument
		storeSignedFile(originalDocument, outZip);

		// Stores the signature
		if (SignatureForm.XAdES.equals(asicSignatureForm)) {

			buildXAdES(enclosedSignature, signature, outZip);
		} else if (SignatureForm.CAdES.equals(asicSignatureForm)) {

			buildCAdES(signature, outZip);
		}
		// Finishes the ZIP (with implicit finish/flush)
		DSSUtils.close(outZip);

		// return the new toSignDocument = ASiC-S
		final byte[] documentBytes = outBytes.toByteArray();
		final String name = toSignDocumentName != null ? toSignDocumentName + ASICS_EXTENSION : null;
		final InMemoryDocument asicSignature = new InMemoryDocument(documentBytes, name, MimeType.ASICS);
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

		try {

			final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
			final DSSDocument signature = validator.getDocument();
			DSSDocument originalDocument = parameters.getDetachedContent();
			// TODO (22/08/2014): This is a List now!
			if (validator.getDetachedContents() == null || validator.getDetachedContents().size() == 0) {

				List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
				detachedContents.add(originalDocument);
				validator.setDetachedContents(detachedContents);
			} else {
				// TODO (22/08/2014): This is a List now!
				originalDocument = validator.getDetachedContents().get(0);
			}

			final DocumentSignatureService specificService = getSpecificService(parameters);
			specificService.setTspSource(tspSource);

			final SignatureParameters xadesParameters = getParameters(parameters);
			xadesParameters.setDetachedContent(originalDocument);
			final DSSDocument signedDocument = specificService.extendDocument(signature, xadesParameters);

			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final ZipOutputStream zip = new ZipOutputStream(output);

			final ZipInputStream input = new ZipInputStream(toExtendDocument.openStream());
			ZipEntry entry = null;
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

		final SignatureParameters specificParameters = new SignatureParameters(parameters);
		final SignatureLevel asicProfile = parameters.getSignatureLevel();
		final SignatureForm asicSignatureForm = parameters.aSiC().getAsicSignatureForm();
		SignatureLevel specificLevel;
		switch (asicProfile) {

			case ASiC_S_BASELINE_B:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_S_BASELINE_T:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_S_BASELINE_LT:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
				break;
			case ASiC_S_BASELINE_LTA:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LTA : SignatureLevel.CAdES_BASELINE_LTA;
				break;
			case ASiC_E_BASELINE_B:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
				break;
			case ASiC_E_BASELINE_T:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
				break;
			case ASiC_E_BASELINE_LT:
				specificLevel = asicSignatureForm == SignatureForm.XAdES ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
				break;
			default:
				throw new DSSException("Unsupported format: " + asicProfile.name());
		}
		specificParameters.setSignatureLevel(specificLevel);
		specificParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		return specificParameters;
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

		final String toSignDocumentName = toSignDocument.getName();
		final ZipEntry entryDocument = new ZipEntry(toSignDocumentName != null ? toSignDocumentName : ZIP_ENTRY_DETACHED_FILE);
		outZip.setLevel(ZipEntry.DEFLATED);

		try {
			outZip.putNextEntry(entryDocument);
			DSSUtils.copy(toSignDocument.openStream(), outZip);
		} catch (IOException e) {
			throw new DSSException(e);
		}
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

		final SignatureForm asicSignatureForm = specificParameters.aSiC().getAsicSignatureForm();
		final DocumentSignatureService underlyingASiCService = specificParameters.getContext().getUnderlyingASiCService(certificateVerifier, asicSignatureForm);
		underlyingASiCService.setTspSource(tspSource);
		return underlyingASiCService;
	}
}