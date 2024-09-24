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

import java.awt.image.BufferedImage;
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

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuild;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuildDataDict;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PdfAnnotation;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.encryption.DSSSecureRandomProvider;
import eu.europa.esig.dss.pdf.encryption.SecureRandomProvider;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.NativePdfBoxVisibleSignatureDrawer;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

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
	protected DSSMessageDigest computeDigest(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(toSignDocument,
					 getPasswordString(parameters.getPasswordProtection()), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
			final DSSMessageDigest messageDigest = signDocumentAndReturnDigest(parameters, signatureValue, os, documentReader);
			if (LOG.isDebugEnabled()) {
				LOG.debug(messageDigest.toString());
			}

			// cache the computed document
			parameters.getPdfSignatureCache().setToBeSignedDocument(resourcesHandler.writeToDSSDocument());

			return messageDigest;

		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	protected DSSDocument signDocument(final DSSDocument toSignDocument, final byte[] cmsSignedData,
			final PAdESCommonParameters parameters) {
		try (

				DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
				OutputStream os = resourcesHandler.createOutputStream();
				PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(toSignDocument,
						getPasswordString(parameters.getPasswordProtection()),
						PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))

		) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			signDocumentAndReturnDigest(parameters, cmsSignedData, os, documentReader);

			DSSDocument signedDocument = resourcesHandler.writeToDSSDocument();
			signedDocument.setMimeType(MimeTypeEnum.PDF);
			return signedDocument;

		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private DSSMessageDigest signDocumentAndReturnDigest(final PAdESCommonParameters parameters, final byte[] cmsSignedData,
			final OutputStream outputStream, final PdfBoxDocumentReader documentReader) {
		PDDocument pdDocument = documentReader.getPDDocument();

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
		SignatureInterface signatureInterface = new SignatureInterface() {

			@Override
			public byte[] sign(InputStream content) throws IOException {

				byte[] b = new byte[8192];
				int count;
				while ((count = content.read(b)) > 0) {
					digest.update(b, 0, count);
				}
				return cmsSignedData;
			}

		};
		
		SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
		final PDSignature pdSignature = createSignatureDictionary(pdDocument, parameters);
		final PDSignatureField pdSignatureField = findExistingSignatureField(pdDocument, fieldParameters);
		if (pdSignatureField != null) {
			setSignatureToField(pdDocument, pdSignatureField, pdSignature);
		}

		try (SignatureOptions options = new SignatureOptions()) {
			options.setPreferredSignatureSize(parameters.getContentSize());

			SignatureImageParameters imageParameters = parameters.getImageParameters();
			if (!imageParameters.isEmpty()) {
				PdfBoxSignatureDrawer signatureDrawer = (PdfBoxSignatureDrawer) loadSignatureDrawer(imageParameters);
				signatureDrawer.init(imageParameters, pdDocument, options);
				if (signatureDrawer instanceof NativePdfBoxVisibleSignatureDrawer) {
					((NativePdfBoxVisibleSignatureDrawer) signatureDrawer).setResourcesHandlerBuilder(resourcesHandlerBuilder);
				}
				
				if (pdSignatureField == null) {
					// check signature field position only for new annotations
					getVisibleSignatureFieldBoxPosition(signatureDrawer, documentReader, fieldParameters);
				}

				int page = fieldParameters.getPage();
				options.setPage(page - ImageUtils.DEFAULT_FIRST_PAGE); // DSS-1138
				
				signatureDrawer.draw();
			}

			pdDocument.addSignature(pdSignature, signatureInterface, options);

			// the document needs to have an ID, if not the current system time is used, 
			// and then the digest of the signed data will be different
			if (pdDocument.getDocumentId() == null) {
				pdDocument.setDocumentId(documentReader.generateDocumentId(parameters));
			}
			digitalSignatureEnhancement(documentReader, parameters);

			checkEncryptedAndSaveIncrementally(pdDocument, outputStream, parameters);

			return new DSSMessageDigest(digestAlgorithm, digest.digest());

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute digest for a PDF : %s", e.getMessage()), e);
		}
	}
	
	private PDSignatureField findExistingSignatureField(final PDDocument pdDocument, final SignatureFieldParameters fieldParameters) {
		String targetFieldId = fieldParameters.getFieldId();
		if (Utils.isStringNotEmpty(targetFieldId)) {
			PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();
			if (acroForm != null) {
				PDField field = acroForm.getField(targetFieldId);
				if (field != null) {
					if (field instanceof PDSignatureField) {
						PDSignatureField signatureField = (PDSignatureField) field;
						PDSignature signature = signatureField.getSignature();
						if (signature != null) {
							throw new IllegalArgumentException(String.format(
									"The signature field '%s' can not be signed since its already signed.", targetFieldId));
						}
						return signatureField;
					} else {
						throw new IllegalArgumentException(String.format("The field '%s' is not a signature field!",
								targetFieldId));
					}
				}
			}
			throw new IllegalArgumentException(String.format("The signature field '%s' does not exist.", targetFieldId));
		}
		return null;
	}

	/**
	 * Creates a new signature dictionary
	 *
	 * Note for developers: keep protected! See <a href="https://github.com/esig/dss/pull/138">PR #138</a>
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

		if (Utils.isStringNotEmpty(parameters.getAppName())) {
			PDPropBuild propBuild = new PDPropBuild(new COSDictionary());
			PDPropBuildDataDict app = new PDPropBuildDataDict();
			app.setName(parameters.getAppName());
			propBuild.setPDPropBuildApp(app);
			signature.setPropBuild(propBuild);
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

	private void setSignatureToField(final PDDocument pdDocument, final PDSignatureField pdSignatureField, final PDSignature pdSignature) {
		setFieldMDP(pdDocument, pdSignatureField, pdSignature);
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
	 * Add FieldMDP TransformMethod if the signature field contains a Lock
	 * See {@link <a href="https://github.com/mkl-public/testarea-pdfbox2/blob/master/src/test/java/mkl/testarea/pdfbox2/sign/CreateSignature.java#L348">link</a>}
	 *
	 * @param pdDocument the document
	 * @param pdSignatureField the signature field
	 * @param pdSignature the signature object
	 */
	private void setFieldMDP(PDDocument pdDocument, PDSignatureField pdSignatureField, PDSignature pdSignature) {
		COSBase lock = pdSignatureField.getCOSObject().getDictionaryObject(COSName.getPDFName(PAdESConstants.LOCK_NAME));
		if (lock instanceof COSDictionary) {
			COSDictionary lockDict = (COSDictionary) lock;
			COSDictionary transformParams = new COSDictionary(lockDict);
			transformParams.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
			transformParams.setName(COSName.V, PAdESConstants.VERSION_DEFAULT);
			transformParams.setDirect(true);
			COSDictionary sigRef = new COSDictionary();
			sigRef.setItem(COSName.TYPE, COSName.SIG_REF);
			sigRef.setItem(COSName.TRANSFORM_METHOD, COSName.getPDFName(PAdESConstants.FIELD_MDP_NAME));
			sigRef.setItem(COSName.TRANSFORM_PARAMS, transformParams);
			sigRef.setItem(COSName.getPDFName(PAdESConstants.DATA_NAME), pdDocument.getDocumentCatalog());
			sigRef.setDirect(true);
			COSArray referenceArray = new COSArray();
			referenceArray.add(sigRef);
			pdSignature.getCOSObject().setItem(COSName.REFERENCE, referenceArray);
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
	protected void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
		COSDictionary sigDict = signature.getCOSObject();

		// DocMDP specific stuff
		COSDictionary transformParameters = new COSDictionary();
		transformParameters.setItem(COSName.TYPE, COSName.getPDFName(PAdESConstants.TRANSFORM_PARAMS_NAME));
		transformParameters.setInt(COSName.P, accessPermissions);
		transformParameters.setName(COSName.V, PAdESConstants.VERSION_DEFAULT);
		transformParameters.setNeedToBeUpdated(true);
		transformParameters.setDirect(true);

		COSDictionary referenceDict = new COSDictionary();
		referenceDict.setItem(COSName.TYPE, COSName.getPDFName(PAdESConstants.SIG_REF_NAME));
		referenceDict.setItem(PAdESConstants.TRANSFORM_METHOD_NAME, COSName.DOCMDP);
		referenceDict.setItem(PAdESConstants.TRANSFORM_PARAMS_NAME, transformParameters);
		referenceDict.setNeedToBeUpdated(true);
		referenceDict.setDirect(true);

		COSArray referenceArray = new COSArray();
		referenceArray.add(referenceDict);
		sigDict.setItem(PAdESConstants.REFERENCE_NAME, referenceArray);
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
	public DSSDocument addDssDictionary(DSSDocument document, PdfValidationDataContainer validationDataForInclusion,
										char[] pwd, boolean includeVRIDict) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 InputStream is = document.openStream();
			 PDDocument pdDocument = PDDocument.load(is, getPasswordString(pwd));
			 PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(pdDocument)) {

			if (!validationDataForInclusion.isEmpty()) {
				final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSObject();
				cosDictionary.setItem(PAdESConstants.DSS_DICTIONARY_NAME,
						buildDSSDictionary(pdDocument, validationDataForInclusion, includeVRIDict));
				cosDictionary.setNeedToBeUpdated(true);
			}
			ensureESICDeveloperExtension1(documentReader);
			
			// encryption is not required (no signature/timestamp is added on the step)
			saveDocumentIncrementally(pdDocument, os);

			DSSDocument extendedDocument = resourcesHandler.writeToDSSDocument();
			extendedDocument.setMimeType(MimeTypeEnum.PDF);
			return extendedDocument;

		} catch (Exception e) {
			throw new DSSException(String.format("Unable to add a new dss dictionary revision : %s", e.getMessage()), e);
		}
	}

	private COSDictionary buildDSSDictionary(PDDocument pdDocument, PdfValidationDataContainer validationDataForInclusion,
											 boolean includeVRIDict)
			throws IOException {
		final COSDictionary dss = new COSDictionary();
		final COSArray certs = new COSArray();
		final COSArray crls = new COSArray();
		final COSArray ocsps = new COSArray();

		final Map<String, COSBase> knownObjects = new HashMap<>();

		Collection<AdvancedSignature> signatures = validationDataForInclusion.getSignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {

			final COSDictionary vriDictionary = new COSDictionary();
			for (AdvancedSignature signature : signatures) {
				COSDictionary sigVriDictionary = new COSDictionary();
				sigVriDictionary.setDirect(true);

				ValidationData validationDataToAdd = new ValidationData();

				ValidationData signatureValidationData = validationDataForInclusion.getAllValidationDataForSignature(signature);
				validationDataToAdd.addValidationData(signatureValidationData);

				if (!validationDataToAdd.isEmpty()) {
					Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
					if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
						COSArray sigCerts = new COSArray();
						for (CertificateToken certificateToken : certificateTokensToAdd) {
							final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
									knownObjects, certificateToken);
							// ensure there is no duplicated references
							if (sigCerts.indexOf(cosObject) == -1) {
								sigCerts.add(cosObject);
								if (certs.indexOf(cosObject) == -1) {
									certs.add(cosObject);
								}
							}
						}
						sigVriDictionary.setItem(PAdESConstants.CERT_ARRAY_NAME_VRI, sigCerts);
					}

					Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
					if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
						COSArray sigCrls = new COSArray();
						for (CRLToken crlToken : crlTokensToAdd) {
							final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
									knownObjects, crlToken);
							if (sigCrls.indexOf(cosObject) == -1) {
								sigCrls.add(cosObject);
								if (crls.indexOf(cosObject) == -1) {
									crls.add(cosObject);
								}
							}
						}
						sigVriDictionary.setItem(PAdESConstants.CRL_ARRAY_NAME_VRI, sigCrls);
					}

					Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
					if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
						COSArray sigOcsps = new COSArray();
						for (OCSPToken ocspToken : ocspTokensToAdd) {
							final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
									knownObjects, ocspToken);
							if (sigOcsps.indexOf(cosObject) == -1) {
								sigOcsps.add(cosObject);
								if (ocsps.indexOf(cosObject) == -1) {
									ocsps.add(cosObject);
								}
							}
						}
						sigVriDictionary.setItem(PAdESConstants.OCSP_ARRAY_NAME_VRI, sigOcsps);
					}

					// We can't use CMSSignedData, the pdSignature content is trimmed (000000)
					String vriKey = ((PAdESSignature) signature).getVRIKey();
					vriDictionary.setItem(vriKey, sigVriDictionary);
				}
			}

			// optional
			if (includeVRIDict) {
				dss.setItem(PAdESConstants.VRI_DICTIONARY_NAME, vriDictionary);
			}

		}

		Collection<TimestampToken> detachedTimestamps = validationDataForInclusion.getDetachedTimestamps();
		if (Utils.isCollectionNotEmpty(detachedTimestamps)) { // for detached timestamps

			ValidationData validationDataToAdd = validationDataForInclusion.getAllValidationData();
			Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
			if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
				for (CertificateToken certificateToken : certificateTokensToAdd) {
					final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
							knownObjects, certificateToken);
					if (certs.indexOf(cosObject) == -1) {
						certs.add(cosObject);
					}
				}
			}
			Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
			if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
				for (CRLToken crlToken : crlTokensToAdd) {
					final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
							knownObjects, crlToken);
					if (crls.indexOf(cosObject) == -1) {
						crls.add(cosObject);
					}
				}
			}
			Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
			if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
				for (OCSPToken ocspToken : validationDataToAdd.getOcspTokens()) {
					final COSBase cosObject = getPdfObjectForToken(pdDocument, validationDataForInclusion,
							knownObjects, ocspToken);
					if (ocsps.indexOf(cosObject) == -1) {
						ocsps.add(cosObject);
					}
				}
			}
		}

		if (certs.size() > 0) {
			dss.setItem(PAdESConstants.CERT_ARRAY_NAME_DSS, certs);
		}
		if (crls.size() > 0) {
			dss.setItem(PAdESConstants.CRL_ARRAY_NAME_DSS, crls);
		}
		if (ocsps.size() > 0) {
			dss.setItem(PAdESConstants.OCSP_ARRAY_NAME_DSS, ocsps);
		}

		return dss;
	}

	private COSBase getPdfObjectForToken(PDDocument pdDocument, PdfValidationDataContainer validationDataContainer,
										 Map<String, COSBase> knownObjects, Token token) throws IOException {
		final String tokenKey = validationDataContainer.getTokenKey(token);
		COSBase object = knownObjects.get(tokenKey);
		if (object != null) {
			return object;
		}

		Long objectNumber = validationDataContainer.getTokenReference(token);
		if (objectNumber == null) {
			COSStream stream = pdDocument.getDocument().createCOSStream();
			try (OutputStream unfilteredStream = stream.createOutputStream()) {
				unfilteredStream.write(token.getEncoded());
				unfilteredStream.flush();
			}
			object = stream;
		} else {
			object = getByObjectNumber(pdDocument, objectNumber);
		}

		knownObjects.put(tokenKey, object);
		return object;
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
	public List<String> getAvailableSignatureFields(final DSSDocument document, final char[] pwd) {
		List<String> result = new ArrayList<>();
		try (InputStream is = document.openStream(); PDDocument pdfDoc = PDDocument.load(is, getPasswordString(pwd))) {
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
	public DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters,
											final char[] pwd) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(document, getPasswordString(pwd), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))) {
			checkPdfPermissions(documentReader, parameters);

			final PDDocument pdfDoc = documentReader.getPDDocument();
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
			}

			PDSignatureField signatureField = new PDSignatureField(acroForm);
			if (Utils.isStringNotBlank(parameters.getFieldId())) {
				signatureField.setPartialName(parameters.getFieldId());
			}

			AnnotationBox annotationBox = getVisibleSignatureFieldBoxPosition(pdfBoxDocumentReader, parameters);
			
			// start counting from TOP of the page
			PDRectangle rect = new PDRectangle(annotationBox.getMinX(), annotationBox.getMinY(),
					annotationBox.getWidth(), annotationBox.getHeight());

			PDPage page = pdfBoxDocumentReader.getPDPage(parameters.getPage());
			PDAnnotationWidget widget = signatureField.getWidgets().get(0);
			widget.setRectangle(rect);
			widget.setPage(page);
			page.getAnnotations().add(widget);

			// Set normal appearance
			PDAppearanceDictionary appearance = PdfBoxUtils.createSignatureAppearanceDictionary(pdfDoc, rect);
			widget.setAppearance(appearance);

			acroForm.getFields().add(signatureField);
			COSArray fields = acroForm.getCOSObject().getCOSArray(COSName.FIELDS);
			if (fields != null) {
				fields.setNeedToBeUpdated(true);
			}

			acroForm.getCOSObject().setNeedToBeUpdated(true);
			signatureField.getCOSObject().setNeedToBeUpdated(true);
			page.getCOSObject().setNeedToBeUpdated(true);

			saveDocumentIncrementally(pdfDoc, os);

			DSSDocument updatedDocument = resourcesHandler.writeToDSSDocument();
			updatedDocument.setName("new-document.pdf");
			updatedDocument.setMimeType(MimeTypeEnum.PDF);
			return updatedDocument;

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to add a new signature field. Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	public DSSDocument previewPageWithVisualSignature(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(toSignDocument,
					 getPasswordString(parameters.getPasswordProtection()), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
			signDocumentAndReturnDigest(parameters, signatureValue, os, documentReader);

			DSSDocument doc = resourcesHandler.writeToDSSDocument();
			return PdfBoxUtils.generateScreenshot(doc, parameters.getPasswordProtection(),
					parameters.getImageParameters().getFieldParameters().getPage(),
					PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting), instantiateResourcesHandler());

		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument previewSignatureField(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(toSignDocument,
					 getPasswordString(parameters.getPasswordProtection()), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			List<PdfAnnotation> originalAnnotations = documentReader.getPdfAnnotations(
					parameters.getImageParameters().getFieldParameters().getPage());

			final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
			signDocumentAndReturnDigest(parameters, signatureValue, os, documentReader);

			DSSDocument doc = resourcesHandler.writeToDSSDocument();
			return getNewSignatureFieldScreenshot(doc, parameters, originalAnnotations);

		} catch (Exception e) {
			throw new DSSException(String.format(
					"An error occurred while building a signature field preview : %s", e.getMessage()), e);
		}
	}

	private DSSDocument getNewSignatureFieldScreenshot(DSSDocument doc, PAdESCommonParameters parameters, List<PdfAnnotation> originalAnnotations) throws IOException {
		try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(doc,
				getPasswordString(parameters.getPasswordProtection()), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting))) {
			List<PdfAnnotation> newAnnotations = reader.getPdfAnnotations(parameters.getImageParameters().getFieldParameters().getPage());
			AnnotationBox pageBox = reader.getPageBox(parameters.getImageParameters().getFieldParameters().getPage());

			PdfAnnotation newField = null;
			for (PdfAnnotation newAnnotation : newAnnotations) {
				boolean found = false;
				for (PdfAnnotation originalAnnotation : originalAnnotations) {
					if (Utils.areStringsEqual(originalAnnotation.getName(), newAnnotation.getName())) {
						found = true;
						break;
					}
				}
				if (!found) {
					newField = newAnnotation;
					break;
				}
			}

			if (newField != null) {
				AnnotationBox fieldBox = newField.getAnnotationBox();
				AnnotationBox box = fieldBox.toPdfPageCoordinates(pageBox.getHeight());

				BufferedImage page = reader.generateImageScreenshot(parameters.getImageParameters().getFieldParameters().getPage());
				BufferedImage annotationRepresentation = page.getSubimage(
						Math.round((box.getMaxX() - box.getWidth())), Math.round((box.getMaxY() - box.getHeight())),
						Math.round(box.getWidth()), Math.round(box.getHeight()));
				return ImageUtils.toDSSDocument(annotationRepresentation, instantiateResourcesHandler());

			} else {
				throw new DSSException("Internal error : unable to extract a new signature field!");
			}

		}
	}

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, char[] passwordProtection)
			throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		return new PdfBoxDocumentReader(dssDocument, getPasswordString(passwordProtection), PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting));
	}

	/**
	 * Returns a String implementation of a password binaries
	 *
	 * @param passwordProtection char array
	 * @return {@link String}
	 */
	private String getPasswordString(char[] passwordProtection) {
		// PdfBox accepts only String implementation of password
		String password = null;
		if (passwordProtection != null) {
			password = new String(passwordProtection);
		}
		return password;
	}

}
