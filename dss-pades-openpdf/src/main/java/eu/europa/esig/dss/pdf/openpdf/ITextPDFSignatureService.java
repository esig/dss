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
import com.lowagie.text.pdf.ByteBuffer;
import com.lowagie.text.pdf.PRIndirectReference;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;
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
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawer;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

	@Override
	protected void checkDocumentPermissions(final DSSDocument toSignDocument, final String pwd) {
		try (InputStream is = toSignDocument.openStream(); PdfReader reader = new PdfReader(is, getPasswordBinary(pwd))) {
			if (!reader.isOpenedWithFullPermissions()) {
				throw new ProtectedDocumentException("Protected document");
			} 
			else if (reader.isEncrypted()) {
				throw new ProtectedDocumentException("Encrypted document");
			}
		} catch (BadPasswordException e) {
			throw new InvalidPasswordException("Encrypted document");
		} catch (DSSException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSException("Unable to check document permissions", e);
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PdfStamper prepareStamper(InputStream pdfData, OutputStream output, PAdESCommonParameters parameters)
			throws IOException {
		try (PdfReader reader = new PdfReader(pdfData, getPasswordBinary(parameters.getPasswordProtection()))) {

			PdfStamper stp = PdfStamper.createSignature(reader, output, '\0', null, true);
			stp.setIncludeFileID(true);
			stp.setOverrideFileId(generateFileId(parameters));

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
					checkVisibleSignatureFieldBoxPosition(signatureDrawer, new ITextDocumentReader(reader), fieldParameters);
				} else {
					signatureDrawer.setSignatureField(fieldItem);
				}

				signatureDrawer.draw();
			}

			PdfDictionary signatureDictionary = createSignatureDictionary(fieldItem, parameters);
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
				signatureDictionary.put(PdfName.M, new PdfDate(cal));
			}

			sap.setCryptoDictionary(signatureDictionary);

			int csize = parameters.getContentSize();
			HashMap exc = new HashMap();
			exc.put(PdfName.CONTENTS, Integer.valueOf((csize * 2) + 2));

			sap.preClose(exc);

			return stp;
		}
	}
	
	private Item findExistingSignatureField(PdfReader reader, SignatureFieldParameters fieldParameters) {
		String signatureFieldId = fieldParameters.getFieldId();
		if (!isDocumentTimestampLayer() && Utils.isStringNotEmpty(signatureFieldId)) {
			AcroFields acroFields = reader.getAcroFields();
			List<String> signatureNames = acroFields.getFieldNamesWithBlankSignatures();
			if (signatureNames.contains(signatureFieldId)) {
				return acroFields.getFieldItem(signatureFieldId);
			}
			throw new IllegalArgumentException(String.format("The signature field with id '%s' does not exist.", signatureFieldId));
		}
		return null;
	}
	
	private PdfDictionary createSignatureDictionary(Item fieldItem, PAdESCommonParameters parameters) {
		PdfDictionary dic;
		if (fieldItem != null) {
			dic = fieldItem.getMerged(0);
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

	private boolean containsFilledSignature(PdfReader reader) {
		AcroFields acroFields = reader.getAcroFields();
		List<String> signatureNames = acroFields.getSignedFieldNames();
		for (String name : signatureNames) {
			PdfDict dictionary = new ITextPdfDict(acroFields.getSignatureDictionary(name));
			PdfSigDictWrapper signatureDictionary = new PdfSigDictWrapper(dictionary);
			if (Utils.isArrayNotEmpty(signatureDictionary.getContents())) {
				return true;
			}
		}
		return false;
	}

	private PdfObject generateFileId(PAdESCommonParameters parameters) {
		try (ByteBuffer buf = new ByteBuffer(90)) {
			String deterministicId = DSSUtils.getDeterministicId(parameters.getSigningDate(), null);
			byte[] id = deterministicId.getBytes();
			buf.append('[').append('<');
			for (int k = 0; k < 16; ++k) {
				buf.appendHex(id[k]);
			}
			buf.append('>').append('<');
			for (int k = 0; k < 16; ++k) {
				buf.appendHex(id[k]);
			}
			buf.append('>').append(']');
			return new PdfLiteral(buf.toByteArray());
		} catch (IOException e) {
			throw new DSSException("Unable to generate the fileId", e);
		}
	}

	@Override
	public byte[] digest(DSSDocument toSignDocument, PAdESCommonParameters parameters) {
		
		checkDocumentPermissions(toSignDocument, parameters.getPasswordProtection());

		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			final byte[] digest = DSSUtils.digest(parameters.getDigestAlgorithm(), sap.getRangeStream());
			if (LOG.isDebugEnabled()) {
				LOG.debug("Base64 messageDigest : {}", Utils.toBase64(digest));
			}
			return digest;
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build message-digest : %s", e.getMessage()), e);
		}
	}

	@Override
	public DSSDocument sign(DSSDocument toSignDocument, byte[] signatureValue, PAdESCommonParameters parameters) {

		checkDocumentPermissions(toSignDocument, parameters.getPasswordProtection());

		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			byte[] pk = signatureValue;
			int csize = parameters.getContentSize();
			if (csize < pk.length) {
				throw new IllegalArgumentException(
						String.format("Unable to save a document. Reason : The signature size [%s] is too small " +
								"for the signature value with a length [%s]. Use setContentSize(...) method " +
								"to define a bigger length.", csize, pk.length));
			}

			byte[] outc = new byte[csize];
			System.arraycopy(pk, 0, outc, 0, pk.length);

			PdfDictionary dic = new PdfDictionary();
			dic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
			sap.close(dic);

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to sign a PDF : %s", e.getMessage()), e);
		}
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, ValidationDataContainer validationDataForInclusion, String pwd) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is, getPasswordBinary(pwd))) {

			PdfStamper stp = new PdfStamper(reader, baos, '\0', true);
			PdfWriter writer = stp.getWriter();

			if (!validationDataForInclusion.isEmpty()) {

				Collection<AdvancedSignature> signatures = validationDataForInclusion.getSignatures();
				Map<String, Long> knownObjects = buildKnownObjects(signatures);

				PdfDictionary catalog = reader.getCatalog();

				PdfDictionary dss = new PdfDictionary();
				PdfDictionary vrim = new PdfDictionary();
				PdfArray ocsps = new PdfArray();
				PdfArray crls = new PdfArray();
				PdfArray certs = new PdfArray();

				for (AdvancedSignature signature : signatures) {
					ValidationData validationDataToAdd = new ValidationData();

					ValidationData signatureValidationData = validationDataForInclusion.getAllValidationDataForSignature(signature);
					validationDataToAdd.addValidationData(signatureValidationData);

					if (!validationDataToAdd.isEmpty()) {
						PdfArray ocsp = new PdfArray();
						PdfArray crl = new PdfArray();
						PdfArray cert = new PdfArray();
						PdfDictionary vri = new PdfDictionary();

						Set<CertificateToken> certificateTokensToAdd = validationDataToAdd.getCertificateTokens();
						if (Utils.isCollectionNotEmpty(certificateTokensToAdd)) {
							for (CertificateToken certToken : certificateTokensToAdd) {
								PdfObject iref = getPdfObjectForToken(certToken, knownObjects, reader, writer);
								cert.add(iref);
								certs.add(iref);
							}
							vri.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_VRI), cert);
						}

						Set<CRLToken> crlTokensToAdd = validationDataToAdd.getCrlTokens();
						if (Utils.isCollectionNotEmpty(crlTokensToAdd)) {
							for (CRLToken crlToken : crlTokensToAdd) {
								PdfObject iref = getPdfObjectForToken(crlToken, knownObjects, reader, writer);
								crl.add(iref);
								crls.add(iref);
							}
							vri.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_VRI), crl);
						}

						Set<OCSPToken> ocspTokensToAdd = validationDataToAdd.getOcspTokens();
						if (Utils.isCollectionNotEmpty(ocspTokensToAdd)) {
							for (OCSPToken ocspToken : validationDataToAdd.getOcspTokens()) {
								PdfObject iref = getPdfObjectForToken(ocspToken, knownObjects, reader, writer);
								ocsp.add(iref);
								ocsps.add(iref);
							}
							vri.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_VRI), ocsp);
						}

						String vriKey = ((PAdESSignature) signature).getVRIKey();
						vrim.put(new PdfName(vriKey), vri);
					}
				}
				dss.put(new PdfName(PAdESConstants.VRI_DICTIONARY_NAME),
						writer.addToBody(vrim, false).getIndirectReference());

				if (ocsps.size() > 0) {
					dss.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_DSS), ocsps);
				}
				if (crls.size() > 0) {
					dss.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_DSS), crls);
				}
				if (certs.size() > 0) {
					dss.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_DSS), certs);
				}
				catalog.put(new PdfName(PAdESConstants.DSS_DICTIONARY_NAME),
						writer.addToBody(dss, false).getIndirectReference());

				stp.getWriter().addToBody(reader.getCatalog(), reader.getCatalog().getIndRef(), false);
			}

			stp.close();

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add DSS dictionary", e);
		}
	}

	private PdfObject getPdfObjectForToken(Token token, Map<String, Long> knownObjects, PdfReader reader, PdfWriter writer)
			throws IOException {
		String tokenKey = getTokenKey(token);
		Long objectNumber = knownObjects.get(tokenKey);
		if (objectNumber == null) {
			PdfStream ps = new PdfStream(token.getEncoded());
			return writer.addToBody(ps, false).getIndirectReference();
		} else {
			return new PRIndirectReference(reader, objectNumber.intValue());
		}
	}

	@Override
	public List<String> getAvailableSignatureFields(final DSSDocument document, final String pwd) {
		try (InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is, getPasswordBinary(pwd))) {
			AcroFields acroFields = reader.getAcroFields();
			return acroFields.getFieldNamesWithBlankSignatures();
		} catch (BadPasswordException e) {
			throw new InvalidPasswordException(e.getMessage());
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to retrieve available signature fields : %s", e.getMessage()), e);
		}
	}
	
	@Override
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters, String pwd) {

		checkDocumentPermissions(document, pwd);
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is, getPasswordBinary(pwd))) {

			PdfStamper stp = new PdfStamper(reader, baos, '\0', true);
			
			AnnotationBox annotationBox = checkVisibleSignatureFieldBoxPosition(new ITextDocumentReader(reader), parameters);
			
			stp.addSignature(parameters.getFieldId(), parameters.getPage(), 
					annotationBox.getMinX(), annotationBox.getMinY(), annotationBox.getMaxX(), annotationBox.getMaxY());

			stp.close();

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add a signature field", e);
		}
	}
	
    private byte[] getPasswordBinary(String currentPassword) {
        byte[] password = null;
        if (currentPassword != null) {
            password = currentPassword.getBytes();
        }
        return password;
    }

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, String passwordProtection) throws IOException {
		return new ITextDocumentReader(dssDocument, getPasswordBinary(passwordProtection));
	}

	@Override
	protected PdfDocumentReader loadPdfDocumentReader(byte[] binaries, String passwordProtection) throws IOException {
		return new ITextDocumentReader(binaries, getPasswordBinary(passwordProtection));
	}

	@Override
	protected List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
			final PdfDocumentReader finalRevisionReader) throws IOException {
		// not supported
		return Collections.emptyList();
	}

}
