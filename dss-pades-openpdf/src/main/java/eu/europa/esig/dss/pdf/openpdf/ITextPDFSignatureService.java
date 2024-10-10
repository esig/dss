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
package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.AcroFields.Item;
import com.lowagie.text.pdf.PRIndirectReference;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;
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
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.modifications.PdfModification;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawer;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawerFactory;
import eu.europa.esig.dss.pdf.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.SignatureDrawer;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.ValidationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of PDFSignatureService using iText
 *
 */
public class ITextPDFSignatureService extends AbstractPDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPDFSignatureService.class);

	/**
	 * Constructor for the ITextPDFSignatureService
	 * 
	 * @param serviceMode
	 *                               current instance is used to generate a
	 *                               DocumentTimestamp or Signature signature layer
	 * @param signatureDrawerFactory
	 *                               drawer factory implementation to be used
	 * 
	 */
	public ITextPDFSignatureService(PDFServiceMode serviceMode, ITextSignatureDrawerFactory signatureDrawerFactory) {
		super(serviceMode, signatureDrawerFactory);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PdfStamper prepareStamper(ITextDocumentReader documentReader, OutputStream output, PAdESCommonParameters parameters)
			throws IOException {
		PdfReader reader = documentReader.getPdfReader();
		PdfStamper stp = PdfStamper.createSignature(reader, output, '\0', null, true);
		stp.setIncludeFileID(true);
		stp.setOverrideFileId(documentReader.generateDocumentId(parameters));
		// See https://github.com/LibrePDF/OpenPDF/pull/814 for settings below
		stp.setUpdateDocInfo(false);
		stp.setUpdateMetadata(false);

		Calendar cal = Calendar.getInstance();
		cal.setTime(parameters.getSigningDate());

		stp.setEnforcedModificationDate(cal);

		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		sap.setAcro6Layers(true);

		SignatureImageParameters imageParameters = parameters.getImageParameters();
		SignatureFieldParameters fieldParameters = imageParameters.getFieldParameters();

		Item fieldItem = findExistingSignatureField(reader, fieldParameters);
		if (!imageParameters.isEmpty()) {
			ITextSignatureDrawer signatureDrawer = (ITextSignatureDrawer) loadSignatureDrawer(imageParameters);
			signatureDrawer.init(imageParameters, reader, sap);

			if (fieldItem == null) {
				getVisibleSignatureFieldBoxPosition(signatureDrawer, documentReader, fieldParameters);
			}

			signatureDrawer.draw();
		}

		PdfDictionary signatureDictionary = createSignatureDictionary(reader, fieldItem, parameters);
		if (PAdESConstants.SIGNATURE_TYPE.equals(getType())) {
			PAdESSignatureParameters signatureParameters = (PAdESSignatureParameters) parameters;

			CertificationPermission permission = signatureParameters.getPermission();
			// A document can contain only one signature field that contains a DocMDP
			// transform method;
			// it shall be the first signed field in the document.
			if (permission != null && !containsFilledSignature(reader)) {
				sap.setCertificationLevel(permission.getCode());
			}

			cal.setTimeZone(signatureParameters.getSigningTimeZone());

			// Set data SignDate directly within PdfSignatureAppearance (since OpenPdf 1.3.32)
			sap.setSignDate(cal);
		}

		sap.setCryptoDictionary(signatureDictionary);

		int csize = parameters.getContentSize();
		HashMap exc = new HashMap();
		exc.put(PdfName.CONTENTS, csize * 2 + 2);

		digitalSignatureEnhancement(documentReader, parameters);
		sap.preClose(exc);

		return stp;
	}
	
	private Item findExistingSignatureField(PdfReader reader, SignatureFieldParameters fieldParameters) {
		String signatureFieldId = fieldParameters.getFieldId();
		if (Utils.isStringNotEmpty(signatureFieldId)) {
			AcroFields acroFields = reader.getAcroFields();
			List<String> signatureNames = acroFields.getFieldNamesWithBlankSignatures();
			if (signatureNames.contains(signatureFieldId)) {
				return acroFields.getFieldItem(signatureFieldId);
			}
			throw new IllegalArgumentException(String.format("The signature field with id '%s' does not exist.", signatureFieldId));
		}
		return null;
	}
	
	private PdfDictionary createSignatureDictionary(PdfReader reader, Item fieldItem, PAdESCommonParameters parameters) {
		PdfDictionary dic;
		if (fieldItem != null) {
			dic = fieldItem.getMerged(0);
			setFieldMDP(reader, dic);
		} else {
			dic = new PdfDictionary();
		}
		
		PdfName type = new PdfName(getType());
		dic.put(PdfName.TYPE, type);
		
		if (Utils.isStringNotEmpty(parameters.getFilter())) {
			dic.put(PdfName.FILTER, new PdfName(parameters.getFilter()));
		}
		if (Utils.isStringNotEmpty(parameters.getSubFilter())) {
			dic.put(PdfName.SUBFILTER, new PdfName(parameters.getSubFilter()));
		}

		if (Utils.isStringNotEmpty(parameters.getAppName())) {
			PdfDictionary propBuildDict = new PdfDictionary();
			dic.put(new PdfName(PAdESConstants.PROP_BUILD), propBuildDict);
			PdfDictionary appDict = new PdfDictionary();
			propBuildDict.put(new PdfName(PAdESConstants.APP), appDict);
			appDict.put(PdfName.NAME, new PdfName(parameters.getAppName()));
		}

		if (PdfName.SIG.equals(type)) {
			
			PAdESSignatureParameters signatureParameters = (PAdESSignatureParameters) parameters;
 
			if (Utils.isStringNotEmpty(signatureParameters.getSignerName())) {
				dic.put(PdfName.NAME, new PdfString(signatureParameters.getSignerName(), PdfObject.TEXT_UNICODE));
			}
			if (Utils.isStringNotEmpty(signatureParameters.getReason())) {
				dic.put(PdfName.REASON, new PdfString(signatureParameters.getReason(), PdfObject.TEXT_UNICODE));
			}
			if (Utils.isStringNotEmpty(signatureParameters.getLocation())) {
				dic.put(PdfName.LOCATION, new PdfString(signatureParameters.getLocation(), PdfObject.TEXT_UNICODE));
			}
			if (Utils.isStringNotEmpty(signatureParameters.getContactInfo())) {
				dic.put(PdfName.CONTACTINFO, new PdfString(signatureParameters.getContactInfo(), PdfObject.TEXT_UNICODE));
			}

		}
		
		return dic;
	}

	/**
	 * Add FieldMDP TransformMethod if the signature field contains a Lock. OpenPDF implementation.
	 *
	 * @param reader {@link PdfReader}
	 * @param sigFieldDictionary {@link PdfDictionary} representing a signature field
	 */
	private void setFieldMDP(PdfReader reader, PdfDictionary sigFieldDictionary) {
		PdfDictionary lockDict = sigFieldDictionary.getAsDict(PdfName.LOCK);
		if (lockDict != null) {
			PdfDictionary transformParams = new PdfDictionary();
			transformParams.putAll(lockDict);
			transformParams.put(PdfName.TYPE, PdfName.TRANSFORMPARAMS);
			transformParams.put(PdfName.V, new PdfName(PAdESConstants.VERSION_DEFAULT));
			PdfDictionary sigRef = new PdfDictionary();
			sigRef.put(PdfName.TYPE, PdfName.SIGREF);
			sigRef.put(PdfName.TRANSFORMMETHOD, PdfName.FIELDMDP);
			sigRef.put(PdfName.TRANSFORMPARAMS, transformParams);
			sigRef.put(PdfName.DATA, reader.getCatalog());
			PdfArray referenceArray = new PdfArray();
			referenceArray.add(sigRef);
			sigFieldDictionary.put(PdfName.REFERENCE, referenceArray);
		}
	}

	private boolean containsFilledSignature(PdfReader reader) {
		AcroFields acroFields = reader.getAcroFields();
		List<String> signatureNames = acroFields.getSignedFieldNames();
		for (String name : signatureNames) {
			PdfDictionary signatureDictionary = acroFields.getSignatureDictionary(name);
			if (signatureDictionary.contains(new PdfName(PAdESConstants.CONTENTS_NAME))) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected DSSMessageDigest computeDigest(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		try (
				DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
				OutputStream os = resourcesHandler.createOutputStream();
				ITextDocumentReader documentReader = new ITextDocumentReader(toSignDocument, getPasswordBytes(parameters.getPasswordProtection()), ITextPdfMemoryUsageSetting.map(pdfMemoryUsageSetting))
			) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			PdfStamper stp = prepareStamper(documentReader, os, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			final byte[] digest = DSSUtils.digest(digestAlgorithm, sap.getRangeStream());
			final DSSMessageDigest messageDigest = new DSSMessageDigest(digestAlgorithm, digest);
			if (LOG.isDebugEnabled()) {
				LOG.debug(messageDigest.toString());
			}

			// Ensure OutputStream to contain the data with preserved /Contents
			PdfDictionary dic = new PdfDictionary();
			byte[] outc = new byte[parameters.getContentSize()];
			dic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
			sap.close(dic);

			// cache the computed document
			parameters.getPdfSignatureCache().setToBeSignedDocument(resourcesHandler.writeToDSSDocument());

			return messageDigest;

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build message-digest : %s", e.getMessage()), e);
		}
	}

	@Override
	protected DSSDocument signDocument(final DSSDocument toSignDocument, final byte[] cmsSignedData,
							final PAdESCommonParameters parameters) {
		try (
				DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
				OutputStream os = resourcesHandler.createOutputStream();
				ITextDocumentReader documentReader = new ITextDocumentReader(toSignDocument, getPasswordBytes(parameters.getPasswordProtection()), ITextPdfMemoryUsageSetting.map(pdfMemoryUsageSetting))
			) {

			final SignatureFieldParameters fieldParameters = parameters.getImageParameters().getFieldParameters();
			checkPdfPermissions(documentReader, fieldParameters);

			PdfStamper stp = prepareStamper(documentReader, os, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			int csize = parameters.getContentSize();
			if (csize < cmsSignedData.length) {
				throw new IllegalArgumentException(
						String.format("Unable to save a document. Reason : The signature size [%s] is too small " +
								"for the signature value with a length [%s]. Use setContentSize(...) method " +
								"to define a bigger length.", csize, cmsSignedData.length));
			}

			byte[] outc = new byte[csize];
			System.arraycopy(cmsSignedData, 0, outc, 0, cmsSignedData.length);

			PdfDictionary dic = new PdfDictionary();
			dic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
			sap.close(dic);

			DSSDocument signedDocument = resourcesHandler.writeToDSSDocument();
			signedDocument.setMimeType(MimeTypeEnum.PDF);
			return signedDocument;

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to sign a PDF : %s", e.getMessage()), e);
		}
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, PdfValidationDataContainer validationDataForInclusion,
										char[] pwd, boolean includeVRIDict) {
		try (DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 InputStream is = document.openStream();
			 PdfReader reader = new PdfReader(is, getPasswordBytes(pwd));
			 ITextDocumentReader documentReader = new ITextDocumentReader(reader)) {

			PdfStamper stp = new PdfStamper(reader, os, '\0', true);
			PdfWriter writer = stp.getWriter();

			if (!validationDataForInclusion.isEmpty()) {
				PdfDictionary catalog = reader.getCatalog();
				PdfDictionary dss = buildDSSDictionary(reader, writer, validationDataForInclusion, includeVRIDict);
				catalog.put(new PdfName(PAdESConstants.DSS_DICTIONARY_NAME),
						writer.addToBody(dss, false).getIndirectReference());

				writer.addToBody(reader.getCatalog(), reader.getCatalog().getIndRef(), false);
			}
			ensureESICDeveloperExtension1(documentReader);

			stp.close();

			DSSDocument signature = resourcesHandler.writeToDSSDocument();
			signature.setMimeType(MimeTypeEnum.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add DSS dictionary", e);
		}
	}

	private PdfDictionary buildDSSDictionary(PdfReader reader, PdfWriter writer,
											 PdfValidationDataContainer validationDataForInclusion,
											 boolean includeVRIDict) throws IOException {
		final PdfDictionary dss = new PdfDictionary();
		final PdfArray ocsps = new PdfArray();
		final PdfArray crls = new PdfArray();
		final PdfArray certs = new PdfArray();

		final Map<String, PdfObject> knownObjects = new HashMap<>();

		Collection<AdvancedSignature> signatures = validationDataForInclusion.getSignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {
			PdfDictionary vrim = new PdfDictionary();

			for (AdvancedSignature signature : signatures) {
				ValidationData validationDataToAdd = new ValidationData();

				ValidationData signatureValidationData = validationDataForInclusion.getAllValidationDataForSignature(signature);
				validationDataToAdd.addValidationData(signatureValidationData);

				if (!validationDataToAdd.isEmpty()) {
					PdfDictionary vri = new PdfDictionary();

					Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
					if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
						PdfArray sigCerts = new PdfArray();
						for (CertificateToken certToken : certificateTokensToAdd) {
							PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
									knownObjects, certToken);
							if (!sigCerts.contains(iref)) {
								sigCerts.add(iref);
								if (!certs.contains(iref)) {
									certs.add(iref);
								}
							}
						}
						vri.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_VRI), sigCerts);
					}

					Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
					if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
						PdfArray sigCrls = new PdfArray();
						for (CRLToken crlToken : crlTokensToAdd) {
							PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
									knownObjects, crlToken);
							if (!sigCrls.contains(iref)) {
								sigCrls.add(iref);
								if (!crls.contains(iref)) {
									crls.add(iref);
								}
							}
						}
						vri.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_VRI), sigCrls);
					}

					Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
					if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
						PdfArray sigOcsps = new PdfArray();
						for (OCSPToken ocspToken : validationDataToAdd.getOcspTokens()) {
							PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
									knownObjects, ocspToken);
							if (!sigOcsps.contains(iref)) {
								sigOcsps.add(iref);
								if (!ocsps.contains(iref)) {
									ocsps.add(iref);
								}
							}
						}
						vri.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_VRI), sigOcsps);
					}

					String vriKey = ((PAdESSignature) signature).getVRIKey();
					vrim.put(new PdfName(vriKey), vri);
				}
			}

			// optional
			if (includeVRIDict) {
				dss.put(new PdfName(PAdESConstants.VRI_DICTIONARY_NAME),
						writer.addToBody(vrim, false).getIndirectReference());
			}

		}

		Collection<TimestampToken> detachedTimestamps = validationDataForInclusion.getDetachedTimestamps();
		if (Utils.isCollectionNotEmpty(detachedTimestamps)) { // for detached timestamps

			ValidationData validationDataToAdd = validationDataForInclusion.getAllValidationData();
			Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
			if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
				for (CertificateToken certToken : certificateTokensToAdd) {
					PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
							knownObjects, certToken);
					if (!certs.contains(iref)) {
						certs.add(iref);
					}
				}
			}
			Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
			if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
				for (CRLToken crlToken : crlTokensToAdd) {
					PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
							knownObjects, crlToken);
					if (!crls.contains(iref)) {
						crls.add(iref);
					}
				}
			}
			Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
			if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
				for (OCSPToken ocspToken : validationDataToAdd.getOcspTokens()) {
					PdfObject iref = getPdfObjectForToken(reader, writer, validationDataForInclusion,
							knownObjects, ocspToken);
					if (!ocsps.contains(iref)) {
						ocsps.add(iref);
					}
				}
			}
		}

		if (ocsps.size() > 0) {
			dss.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_DSS), ocsps);
		}
		if (crls.size() > 0) {
			dss.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_DSS), crls);
		}
		if (certs.size() > 0) {
			dss.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_DSS), certs);
		}

		return dss;
	}

	private PdfObject getPdfObjectForToken(PdfReader reader, PdfWriter writer,
										   PdfValidationDataContainer validationDataContainer,
										   Map<String, PdfObject> knownObjects, Token token) throws IOException {
		final String tokenKey = validationDataContainer.getTokenKey(token);
		PdfObject object = knownObjects.get(tokenKey);
		if (object != null) {
			return object;
		}

		Long objectNumber = validationDataContainer.getTokenReference(token);
		if (objectNumber == null) {
			PdfStream ps = new PdfStream(token.getEncoded());
			object = writer.addToBody(ps, false).getIndirectReference();
		} else {
			object = new PRIndirectReference(reader, objectNumber.intValue());
		}

		knownObjects.put(tokenKey, object);
		return object;
	}

	@Override
	public List<String> getAvailableSignatureFields(final DSSDocument document, final char[] pwd) {
		try (InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is, getPasswordBytes(pwd))) {
			AcroFields acroFields = reader.getAcroFields();
			return acroFields.getFieldNamesWithBlankSignatures();
		} catch (BadPasswordException e) {
			throw new InvalidPasswordException(e.getMessage());
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to retrieve available signature fields : %s", e.getMessage()), e);
		}
	}
	
	@Override
	public DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters,
											final char[] pwd) {
		try (
				DSSResourcesHandler resourcesHandler = instantiateResourcesHandler();
				OutputStream os = resourcesHandler.createOutputStream();
				ITextDocumentReader documentReader = new ITextDocumentReader(document, getPasswordBytes(pwd), ITextPdfMemoryUsageSetting.map(pdfMemoryUsageSetting))
			) {
			checkPdfPermissions(documentReader, parameters);

			final PdfReader reader = documentReader.getPdfReader();
			if (reader.getNumberOfPages() < parameters.getPage()) {
				throw new IllegalArgumentException(String.format("The page number '%s' does not exist in the file!",
						parameters.getPage()));
			}

			PdfStamper stp = new PdfStamper(reader, os, '\0', true);
			
			AnnotationBox annotationBox = getVisibleSignatureFieldBoxPosition(new ITextDocumentReader(reader), parameters);
			
			stp.addSignature(parameters.getFieldId(), parameters.getPage(),
					annotationBox.getMinX(), annotationBox.getMinY(), annotationBox.getMaxX(), annotationBox.getMaxY());

			stp.close();

			DSSDocument signature = resourcesHandler.writeToDSSDocument();
			signature.setMimeType(MimeTypeEnum.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add a signature field", e);
		}
	}

	@Override
	protected AnnotationBox getVisibleSignatureFieldBoxPosition(SignatureDrawer signatureDrawer, PdfDocumentReader documentReader,
																SignatureFieldParameters parameters) throws IOException {
		AnnotationBox annotationBox =  super.getVisibleSignatureFieldBoxPosition(signatureDrawer, documentReader, parameters);
		return alignRelativelyPageBox(documentReader, parameters, annotationBox);
	}

	@Override
	protected AnnotationBox getVisibleSignatureFieldBoxPosition(PdfDocumentReader reader, SignatureFieldParameters parameters) throws IOException {
		AnnotationBox annotationBox = super.getVisibleSignatureFieldBoxPosition(reader, parameters);
		return alignRelativelyPageBox(reader, parameters, annotationBox);
	}

	private AnnotationBox alignRelativelyPageBox(PdfDocumentReader reader, SignatureFieldParameters parameters, AnnotationBox annotationBox) {
		AnnotationBox pageBox = reader.getPageBox(parameters.getPage());
		int pageRotation = reader.getPageRotation(parameters.getPage());
		return ImageRotationUtils.rotateRelativelyWrappingBox(annotationBox, pageBox, pageRotation);
	}

	@Override
	public DSSDocument previewPageWithVisualSignature(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		throw new UnsupportedOperationException("Screenshot feature is not supported by Open PDF");
	}

	@Override
	public DSSDocument previewSignatureField(final DSSDocument toSignDocument, final PAdESCommonParameters parameters) {
		throw new UnsupportedOperationException("Screenshot feature is not supported by Open PDF");
	}

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, char[] passwordProtection) throws IOException {
		return new ITextDocumentReader(dssDocument, getPasswordBytes(passwordProtection), ITextPdfMemoryUsageSetting.map(pdfMemoryUsageSetting));
	}

	@Override
	protected List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
														 final PdfDocumentReader finalRevisionReader) {
		// not supported
		return Collections.emptyList();
	}

	private byte[] getPasswordBytes(char[] passwordProtection) {
		if (Utils.isArrayNotEmpty(passwordProtection)) {
			// OpenPdf uses byte[] implementation of a password.
			// The conversion translates the password without String usage.
			final java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passwordProtection));
			final byte[] bytes = new byte[byteBuffer.limit()];
			byteBuffer.get(bytes);
			return bytes;
		}
		return null;
	}

}
