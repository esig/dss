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
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.encryption.DSSSecureRandomProvider;
import eu.europa.esig.dss.pdf.encryption.SecureRandomProvider;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Implementation of PDFSignatureService using PDFBox
 *
 */
public class PdfBoxSignatureService extends AbstractPDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxSignatureService.class);

	/** Used to generate encrypted content for protected documents */
	private SecureRandomProvider secureRandomProvider;

	/**
	 * Set the {@code SecureRandomProvider}. Allows modifying a custom behavior for signing of encrypted documents.
	 * 
	 * @param secureRandomProvider {@link SecureRandomProvider}
	 */
	public void setSecureRandomProvider(SecureRandomProvider secureRandomProvider) {
		Objects.requireNonNull(secureRandomProvider, "SecureRandomProvider cannot be null");
		this.secureRandomProvider = secureRandomProvider;
	}

	/**
	 * Constructor for the PdfBoxSignatureService
	 * 
	 * @param serviceMode current instance is used to generate DocumentTimestamp or
	 *                    Signature signature layer
	 * @param signatureDrawerFactory
	 *                    drawer factory implementation to be used
	 * 
	 */
	public PdfBoxSignatureService(PDFServiceMode serviceMode, PdfBoxSignatureDrawerFactory signatureDrawerFactory) {
		super(serviceMode, signatureDrawerFactory);
	}

	@Override
	protected void checkDocumentPermissions(final DSSDocument document, final String pwd) {
		try (InputStream is = document.openStream(); PDDocument pdDocument = PDDocument.load(is, pwd)) {

			AccessPermission accessPermission = pdDocument.getCurrentAccessPermission();
			if (accessPermission.isReadOnly()) {
				throw new ProtectedDocumentException("The document cannot be modified (read-only)");
			}

			if (!accessPermission.canModify()) {
				throw new ProtectedDocumentException("Cannot modify the document");
			}

			if (!accessPermission.canModifyAnnotations()) {
				throw new ProtectedDocumentException("Cannot modify the annotation");
			}

			if (!accessPermission.canFillInForm()) {
				throw new ProtectedDocumentException("Cannot fill in form");
			}
			
		} catch (InvalidPasswordException e) {
			throw new eu.europa.esig.dss.pades.exception.InvalidPasswordException("The document is encrypted (password is invalid)");
			
		} catch (DSSException e) {
			throw e;
			
		} catch (Exception e) {
			throw new DSSException("Unable to check document", e);
			
		}
	}

	@Override
	public byte[] digest(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		checkDocumentPermissions(toSignDocument, parameters.getPasswordProtection());

		final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				InputStream is = toSignDocument.openStream();
				PDDocument pdDocument = PDDocument.load(is, parameters.getPasswordProtection())) {

			final byte[] digest = signDocumentAndReturnDigest(parameters, signatureValue, outputStream, pdDocument);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Base64 messageDigest : {}", Utils.toBase64(digest));
			}
			return digest;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument sign(final DSSDocument toSignDocument, final byte[] signatureValue,
			final PAdESCommonParameters parameters) {
		checkDocumentPermissions(toSignDocument, parameters.getPasswordProtection());

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = toSignDocument.openStream();
				PDDocument pdDocument = PDDocument.load(is, parameters.getPasswordProtection())) {

			signDocumentAndReturnDigest(parameters, signatureValue, baos, pdDocument);

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private byte[] signDocumentAndReturnDigest(final PAdESCommonParameters parameters, final byte[] signatureBytes,
			final OutputStream fileOutputStream, final PDDocument pdDocument) {

		final MessageDigest digest = DSSUtils.getMessageDigest(parameters.getDigestAlgorithm());
		SignatureInterface signatureInterface = new SignatureInterface() {

			@Override
			public byte[] sign(InputStream content) throws IOException {

				byte[] b = new byte[4096];
				int count;
				while ((count = content.read(b)) > 0) {
					digest.update(b, 0, count);
				}
				return signatureBytes;
			}
		};
		
		SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
		final PDSignature pdSignature = createSignatureDictionary(pdDocument, parameters);
		final PDSignatureField pdSignatureField = findExistingSignatureField(pdDocument, fieldParameters);
		if (pdSignatureField != null) {
			setSignatureToField(pdSignatureField, pdSignature);
		}
		
		try (SignatureOptions options = new SignatureOptions()) {
			options.setPreferredSignatureSize(parameters.getContentSize());

			SignatureImageParameters imageParameters = parameters.getImageParameters();
			if (!imageParameters.isEmpty()) {
				PdfBoxSignatureDrawer signatureDrawer = (PdfBoxSignatureDrawer) loadSignatureDrawer(imageParameters);
				signatureDrawer.init(imageParameters, pdDocument, options);
				
				if (pdSignatureField == null) {
					// check signature field position only for new annotations
					checkVisibleSignatureFieldBoxPosition(signatureDrawer, new PdfBoxDocumentReader(pdDocument), fieldParameters);
				} else {
					signatureDrawer.setSignatureField(pdSignatureField);
				}
				
				signatureDrawer.draw();
			}

			pdDocument.addSignature(pdSignature, signatureInterface, options);

			// the document needs to have an ID, if not the current system time is used, 
			// and then the digest of the signed data will be different
			if (pdDocument.getDocumentId() == null) {
				pdDocument.setDocumentId(parameters.getSigningDate().getTime());
			}
			checkEncryptedAndSaveIncrementally(pdDocument, fileOutputStream, parameters);

			return digest.digest();

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute digest for a PDF : %s", e.getMessage()), e);
		}
	}
	
	private PDSignatureField findExistingSignatureField(final PDDocument pdDocument, final SignatureFieldParameters fieldParameters) {
		String targetFieldId = fieldParameters.getFieldId();
		if (!isDocumentTimestampLayer() && Utils.isStringNotEmpty(targetFieldId)) {
			PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();
			if (acroForm != null) {
				PDSignatureField signatureField = (PDSignatureField) acroForm.getField(targetFieldId);
				if (signatureField != null) {
					PDSignature signature = signatureField.getSignature();
					if (signature != null) {
						throw new IllegalArgumentException(String.format(
								"The signature field '%s' can not be signed since its already signed.", targetFieldId));
					}
					return signatureField;
				}
			}
			throw new IllegalArgumentException("The signature field '" + targetFieldId + "' does not exist.");
		}
		return null;
	}

	/**
	 * Creates a new signature dictionary
	 *
	 * Note for developers: keep protected! See https://github.com/esig/dss/pull/138
	 *
	 * @param pdDocument {@link PDDocument}
	 * @param parameters {@link PAdESCommonParameters}
	 * @return {@link PDSignature}
	 */
	protected PDSignature createSignatureDictionary(final PDDocument pdDocument, final PAdESCommonParameters parameters) {
		final PDSignature signature = new PDSignature();
		
		COSName currentType = COSName.getPDFName(getType());
		signature.setType(currentType);

		if (Utils.isStringNotEmpty(parameters.getFilter())) {
			signature.setFilter(COSName.getPDFName(parameters.getFilter()));
		}
		// sub-filter for basic and PAdES Part 2 signatures
		if (Utils.isStringNotEmpty(parameters.getSubFilter())) {
			signature.setSubFilter(COSName.getPDFName(parameters.getSubFilter()));
		}

		if (COSName.SIG.equals(currentType)) {

			PAdESSignatureParameters signatureParameters = (PAdESSignatureParameters) parameters;

			if (Utils.isStringNotEmpty(signatureParameters.getSignerName())) {
				signature.setName(signatureParameters.getSignerName());
			}

			if (Utils.isStringNotEmpty(signatureParameters.getContactInfo())) {
				signature.setContactInfo(signatureParameters.getContactInfo());
			}

			if (Utils.isStringNotEmpty(signatureParameters.getLocation())) {
				signature.setLocation(signatureParameters.getLocation());
			}

			if (Utils.isStringNotEmpty(signatureParameters.getReason())) {
				signature.setReason(signatureParameters.getReason());
			}

			CertificationPermission permission = signatureParameters.getPermission();
			// A document can contain only one signature field that contains a DocMDP
			// transform method;
			// it shall be the first signed field in the document.
			if (permission != null && !containsFilledSignature(pdDocument)) {
				setMDPPermission(pdDocument, signature, permission.getCode());
			}

			// the signing date, needed for valid signature
			final Calendar cal = Calendar.getInstance();
			cal.setTime(signatureParameters.getSigningDate());
			cal.setTimeZone(signatureParameters.getSigningTimeZone());
			signature.setSignDate(cal);
		}
		
		return signature;
	}

	private void setSignatureToField(final PDSignatureField pdSignatureField, final  PDSignature pdSignature) {
		pdSignatureField.getCOSObject().setItem(COSName.V, pdSignature);
	}

	private boolean containsFilledSignature(PDDocument pdDocument) {
		try {
			List<PDSignature> signatures = pdDocument.getSignatureDictionaries();
			for (PDSignature pdSignature : signatures) {
				if (pdSignature.getCOSObject().containsKey(COSName.BYTERANGE)) {
					return true;
				}
			}
			return false;
		} catch (IOException e) {
			LOG.warn("Cannot read the existing signature(s)", e);
			return false;
		}
	}

	/**
	 * Set the access permissions granted for this document in the DocMDP transform
	 * parameters dictionary. Details are described in the table "Entries in the
	 * DocMDP transform parameters dictionary" in the PDF specification.
	 *
	 * @param doc               The document.
	 * @param signature         The signature object.
	 * @param accessPermissions The permission value (1, 2 or 3).
	 */
	public void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
		COSDictionary sigDict = signature.getCOSObject();

		// DocMDP specific stuff
		COSDictionary transformParameters = new COSDictionary();
		transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
		transformParameters.setInt(COSName.P, accessPermissions);
		transformParameters.setName(COSName.V, "1.2");
		transformParameters.setNeedToBeUpdated(true);

		COSDictionary referenceDict = new COSDictionary();
		referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
		referenceDict.setItem("TransformMethod", COSName.DOCMDP);
		referenceDict.setItem("TransformParams", transformParameters);
		referenceDict.setNeedToBeUpdated(true);

		COSArray referenceArray = new COSArray();
		referenceArray.add(referenceDict);
		sigDict.setItem("Reference", referenceArray);
		referenceArray.setNeedToBeUpdated(true);

		// Document Catalog
		COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
		COSDictionary permsDict = new COSDictionary();
		catalogDict.setItem(COSName.PERMS, permsDict);
		permsDict.setItem(COSName.DOCMDP, signature);
		catalogDict.setNeedToBeUpdated(true);
		permsDict.setNeedToBeUpdated(true);
	}

	/**
	 * Checks if the document is encrypted and saves incrementally to {@code outputStream}
	 *
	 * @param pdDocument {@link PDDocument} to check and save
	 * @param outputStream {@link OutputStream} to save the content to
	 * @param parameters {@link PAdESCommonParameters}
	 */
	public void checkEncryptedAndSaveIncrementally(PDDocument pdDocument, OutputStream outputStream,
												   PAdESCommonParameters parameters) {
		try {
			if (pdDocument.isEncrypted()) {
				SecureRandom secureRandom = getSecureRandomProvider(parameters).getSecureRandom();
				pdDocument.getEncryption().getSecurityHandler().setCustomSecureRandom(secureRandom);
			}
			saveDocumentIncrementally(pdDocument, outputStream);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to save a document. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Saves the document incrementally
	 *
	 * @param pdDocument {@link PDDocument} to save
	 * @param outputStream {@link OutputStream} to save incremental update to
	 */
	public void saveDocumentIncrementally(PDDocument pdDocument, OutputStream outputStream) {
		try {
			pdDocument.saveIncremental(outputStream);
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to save a document. Reason : %s", e.getMessage()), e);
		}
	}
	
	private SecureRandomProvider getSecureRandomProvider(PAdESCommonParameters parameters) {
		if (secureRandomProvider == null) {
			secureRandomProvider = new DSSSecureRandomProvider(parameters);
		}
		return secureRandomProvider;
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, ValidationDataContainer validationDataForInclusion, String pwd) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = document.openStream();
				PDDocument pdDocument = PDDocument.load(is, pwd)) {

			if (!validationDataForInclusion.isEmpty()) {
				final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSObject();
				cosDictionary.setItem(PAdESConstants.DSS_DICTIONARY_NAME, buildDSSDictionary(pdDocument, validationDataForInclusion));
				cosDictionary.setNeedToBeUpdated(true);
			}
			
			// encryption is not required (no signature/timestamp is added on the step)
			saveDocumentIncrementally(pdDocument, baos);

			DSSDocument inMemoryDocument = new InMemoryDocument(baos.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;

		} catch (Exception e) {
			throw new DSSException(String.format("Unable to add a new dss dictionary revision : %s", e.getMessage()), e);
		}
	}

	private COSDictionary buildDSSDictionary(PDDocument pdDocument, ValidationDataContainer validationDataForInclusion)
			throws IOException {
		COSDictionary dss = new COSDictionary();

		Collection<AdvancedSignature> signatures = validationDataForInclusion.getSignatures();
		Map<String, Long> knownObjects = buildKnownObjects(signatures);

		Map<String, COSStream> streams = new HashMap<>();

		ValidationData allValidationData = validationDataForInclusion.getAllValidationData();

		COSDictionary vriDictionary = new COSDictionary();
		for (AdvancedSignature signature : signatures) {
			COSDictionary sigVriDictionary = new COSDictionary();
			sigVriDictionary.setDirect(true);

			ValidationData validationDataToAdd = new ValidationData();

			ValidationData signatureValidationData = validationDataForInclusion.getAllValidationDataForSignature(signature);
			validationDataToAdd.addValidationData(signatureValidationData);

			if (!validationDataToAdd.isEmpty()) {
				Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
				if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
					sigVriDictionary.setItem(PAdESConstants.CERT_ARRAY_NAME_VRI,
							buildArray(pdDocument, streams, certificateTokensToAdd, knownObjects));
				}

				Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
				if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
					sigVriDictionary.setItem(PAdESConstants.CRL_ARRAY_NAME_VRI,
							buildArray(pdDocument, streams, crlTokensToAdd, knownObjects));
				}

				Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
				if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
					sigVriDictionary.setItem(PAdESConstants.OCSP_ARRAY_NAME_VRI,
							buildArray(pdDocument, streams, ocspTokensToAdd, knownObjects));
				}

				// We can't use CMSSignedData, the pdSignature content is trimmed (000000)
				String vriKey = ((PAdESSignature) signature).getVRIKey();
				vriDictionary.setItem(vriKey, sigVriDictionary);
			}
		}
		dss.setItem(PAdESConstants.VRI_DICTIONARY_NAME, vriDictionary);

		Set<CertificateToken> allCertificateTokens = allValidationData.getCertificateTokens();
		if (Utils.isCollectionNotEmpty(allCertificateTokens)) {
			dss.setItem(PAdESConstants.CERT_ARRAY_NAME_DSS,
					buildArray(pdDocument, streams, allCertificateTokens, knownObjects));
		}

		Set<OCSPToken> allOCSPTokens = allValidationData.getOcspTokens();
		if (Utils.isCollectionNotEmpty(allOCSPTokens)) {
			dss.setItem(PAdESConstants.OCSP_ARRAY_NAME_DSS, buildArray(pdDocument, streams, allOCSPTokens, knownObjects));
		}

		Set<CRLToken> allCRLTokens = allValidationData.getCrlTokens();
		if (Utils.isCollectionNotEmpty(allCRLTokens)) {
			dss.setItem(PAdESConstants.CRL_ARRAY_NAME_DSS, buildArray(pdDocument, streams, allCRLTokens, knownObjects));
		}

		return dss;
	}

	private COSArray buildArray(PDDocument pdDocument, Map<String, COSStream> streams,
			Collection<? extends Token> tokens, Map<String, Long> knownObjects) throws IOException {
		COSArray array = new COSArray();
		// avoid duplicate CRLs
		List<String> currentObjIds = new ArrayList<>();
		for (Token token : tokens) {
			String tokenKey = getTokenKey(token);
			if (!currentObjIds.contains(tokenKey)) {
				Long objectNumber = knownObjects.get(tokenKey);
				if (objectNumber == null) {
					COSStream stream = streams.get(tokenKey);
					if (stream == null) {
						stream = pdDocument.getDocument().createCOSStream();
						try (OutputStream unfilteredStream = stream.createOutputStream()) {
							unfilteredStream.write(token.getEncoded());
							unfilteredStream.flush();
						}
						streams.put(tokenKey, stream);
					}
					array.add(stream);
				} else {
					COSObject foundCosObject = getByObjectNumber(pdDocument, objectNumber);
					array.add(foundCosObject);
				}
				currentObjIds.add(tokenKey);
			}
		}
		return array;
	}

	private COSObject getByObjectNumber(PDDocument pdDocument, Long objectNumber) {
		List<COSObject> objects = pdDocument.getDocument().getObjects();
		for (COSObject cosObject : objects) {
			if (cosObject.getObjectNumber() == objectNumber) {
				return cosObject;
			}
		}
		return null;
	}

	@Override
	public List<String> getAvailableSignatureFields(final DSSDocument document, final String pwd) {
		List<String> result = new ArrayList<>();
		try (InputStream is = document.openStream(); PDDocument pdfDoc = PDDocument.load(is, pwd)) {
			List<PDSignatureField> signatureFields = pdfDoc.getSignatureFields();
			for (PDSignatureField pdSignatureField : signatureFields) {
				PDSignature signature = pdSignatureField.getSignature();
				if (signature == null) {
					result.add(pdSignatureField.getPartialName());
				}
			}
		} catch (InvalidPasswordException e) {
			throw new eu.europa.esig.dss.pades.exception.InvalidPasswordException(e.getMessage());
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to retrieve signature fields. Reason : %s", e.getMessage()), e);
		}
		return result;
	}

	@Override
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters, String pwd) {
		checkDocumentPermissions(document, pwd);
		
		try (InputStream is = document.openStream();
				PDDocument pdfDoc = PDDocument.load(is, pwd);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

			if (pdfDoc.getPages().getCount() < parameters.getPage()) {
				throw new IllegalArgumentException(String.format("The page number '%s' does not exist in the file!", parameters.getPage()));
			}
			
			PdfBoxDocumentReader pdfBoxDocumentReader = new PdfBoxDocumentReader(pdfDoc);

			PDDocumentCatalog catalog = pdfDoc.getDocumentCatalog();
			catalog.getCOSObject().setNeedToBeUpdated(true);

			PDAcroForm acroForm = catalog.getAcroForm();
			if (acroForm == null) {
				acroForm = new PDAcroForm(pdfDoc);
				catalog.setAcroForm(acroForm);

				// Set default appearance
				PDResources resources = new PDResources();
				resources.put(COSName.getPDFName("Helv"), PDType1Font.HELVETICA);
				acroForm.setDefaultResources(resources);
				acroForm.setDefaultAppearance("/Helv 0 Tf 0 g");
			}

			PDSignatureField signatureField = new PDSignatureField(acroForm);
			if (Utils.isStringNotBlank(parameters.getFieldId())) {
				signatureField.setPartialName(parameters.getFieldId());
			}

			AnnotationBox annotationBox = checkVisibleSignatureFieldBoxPosition(pdfBoxDocumentReader, parameters);
			
			// start counting from TOP of the page
			PDRectangle rect = new PDRectangle(annotationBox.getMinX(), annotationBox.getMinY(),
					annotationBox.getWidth(), annotationBox.getHeight());

			PDPage page = pdfBoxDocumentReader.getPDPage(parameters.getPage());
			PDAnnotationWidget widget = signatureField.getWidgets().get(0);
			widget.setRectangle(rect);
			widget.setPage(page);
			page.getAnnotations().add(widget);

			acroForm.getFields().add(signatureField);

			acroForm.getCOSObject().setNeedToBeUpdated(true);
			signatureField.getCOSObject().setNeedToBeUpdated(true);
			page.getCOSObject().setNeedToBeUpdated(true);

			saveDocumentIncrementally(pdfDoc, baos);

			return new InMemoryDocument(baos.toByteArray(), "new-document.pdf", MimeType.PDF);

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to add a new signature field. Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, String passwordProtection) throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		return new PdfBoxDocumentReader(dssDocument, passwordProtection);
	}

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(byte[] binaries, String passwordProtection) throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		return new PdfBoxDocumentReader(binaries, passwordProtection);
	}

}
