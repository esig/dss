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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import eu.europa.esig.dss.pades.EncryptedDocumentException;
import eu.europa.esig.dss.pades.InvalidPasswordException;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.ProtectedDocumentException;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawer;
import eu.europa.esig.dss.pdf.openpdf.visible.ITextSignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

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
	 *                               current instance is used to generate
	 *                               DocumentTypestamp or Signature signature layer
	 * 
	 */
	public ITextPDFSignatureService(PDFServiceMode serviceMode, ITextSignatureDrawerFactory signatureDrawerFactory) {
		super(serviceMode, signatureDrawerFactory);
	}

	@Override
	protected void checkDocumentPermissions(DSSDocument toSignDocument) {
		try (InputStream is = toSignDocument.openStream(); PdfReader reader = new PdfReader(is)) {
			if (!reader.isOpenedWithFullPermissions()) {
				throw new ProtectedDocumentException("Protected document");
			} else if (reader.isEncrypted()) {
				throw new EncryptedDocumentException("Encrypted document");
			}
		} catch (BadPasswordException e) {
			throw new EncryptedDocumentException("Encrypted document");
		} catch (DSSException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSException("Unable to check document permissions", e);
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PdfStamper prepareStamper(InputStream pdfData, OutputStream output, PAdESCommonParameters parameters)
			throws IOException {
		
		PdfReader reader = new PdfReader(pdfData);
		PdfStamper stp = PdfStamper.createSignature(reader, output, '\0', null, true);
		stp.setIncludeFileID(true);
		stp.setOverrideFileId(generateFileId(parameters));

		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		sap.setAcro6Layers(true);

		PdfDictionary dic = null;
		if (!isDocumentTimestampLayer() && Utils.isStringNotEmpty(parameters.getFieldId())) {
			dic = findExistingSignature(reader, parameters.getFieldId());
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

		Calendar cal = Calendar.getInstance();
		cal.setTime(parameters.getSigningDate());

		stp.setEnforcedModificationDate(cal);

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

			CertificationPermission permission = signatureParameters.getPermission();
			// A document can contain only one signature field that contains a DocMDP
			// transform method;
			// it shall be the first signed field in the document.
			if (permission != null && !containsFilledSignature(reader)) {
				sap.setCertificationLevel(permission.getCode());
			}

			dic.put(PdfName.M, new PdfDate(cal));

		}

		sap.setCryptoDictionary(dic);

		SignatureImageParameters sip = parameters.getImageParameters();
		if (sip != null && signatureDrawerFactory != null) {
			ITextSignatureDrawer signatureDrawer = (ITextSignatureDrawer) signatureDrawerFactory
					.getSignatureDrawer(sip);
			signatureDrawer.init(parameters.getFieldId(), sip, sap);
			signatureDrawer.draw();
		}

		int csize = parameters.getContentSize();
		HashMap exc = new HashMap();
		exc.put(PdfName.CONTENTS, Integer.valueOf((csize * 2) + 2));

		sap.preClose(exc);

		return stp;
	}

	private PdfDictionary findExistingSignature(PdfReader reader, String signatureFieldId) {
		AcroFields acroFields = reader.getAcroFields();
		List<String> signatureNames = acroFields.getFieldNamesWithBlankSignatures();
		if (signatureNames.contains(signatureFieldId)) {
			Item item = acroFields.getFieldItem(signatureFieldId);
			return item.getMerged(0);
		}
		throw new DSSException("The signature field '" + signatureFieldId + "' does not exist.");
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
		
		checkDocumentPermissions(toSignDocument);

		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			final byte[] digest = DSSUtils.digest(parameters.getDigestAlgorithm(), sap.getRangeStream());
			if (LOG.isDebugEnabled()) {
				LOG.debug("Base64 messageDigest : {}", Utils.toBase64(digest));
			}
			return digest;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument sign(DSSDocument toSignDocument, byte[] signatureValue, PAdESCommonParameters parameters) {

		checkDocumentPermissions(toSignDocument);

		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			byte[] pk = signatureValue;
			int csize = parameters.getContentSize();
			if (csize < pk.length) {
				throw new DSSException(
						String.format("The signature size [%s] is too small for the signature value with a length [%s]",
								csize, pk.length));
			}

			byte[] outc = new byte[csize];
			System.arraycopy(pk, 0, outc, 0, pk.length);

			PdfDictionary dic = new PdfDictionary();
			dic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
			sap.close(dic);

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	protected List<PdfRevision> getSignatures(CertificatePool validationCertPool, DSSDocument document) {
		List<PdfRevision> result = new ArrayList<>();

		try (InputStream is = document.openStream(); PdfReader reader = new PdfReader(is, getPasswordBinary(passwordProtection))) {
			AcroFields af = reader.getAcroFields();

			final PdfDssDict dssDictionary = getDSSDictionary(reader);
			
			Map<PdfSignatureDictionary, List<String>> sigDictionaries = extractSigDictionaries(af);

			for (Map.Entry<PdfSignatureDictionary, List<String>> sigDictEntry : sigDictionaries.entrySet()) {
				PdfSignatureDictionary signatureDictionary = sigDictEntry.getKey();
				List<String> fieldNames = sigDictEntry.getValue();
				try {
					LOG.info("Signature field name: {}", fieldNames);
					
					final int[] byteRange = signatureDictionary.getSignatureByteRange();
	
					validateByteRange(byteRange);
	
					final byte[] cms = signatureDictionary.getContents();
					byte[] signedContent = DSSUtils.EMPTY_BYTE_ARRAY;
					if (!isContentValueEqualsByteRangeExtraction(document, byteRange, cms, fieldNames)) {
						LOG.warn("Signature {} is skipped. SIWA detected !", fieldNames);
					} else {
						signedContent = getSignedContent(document, byteRange);
					}
	
					boolean signatureCoversWholeDocument = af.signatureCoversWholeDocument(fieldNames.get(0));
	
					if (isDocTimestamp(signatureDictionary)) {
	
						PdfDssDict timestampedRevisionDssDict = null;
	
						// LT or LTA
						if (dssDictionary != null) {
							// obtain covered DSS dictionary if already exist
							timestampedRevisionDssDict = getDSSDictionaryPresentInRevision(getOriginalBytes(byteRange, signedContent));
						}
	
						result.add(new PdfDocTimestampRevision(cms, signatureDictionary, timestampedRevisionDssDict, fieldNames, 
								validationCertPool, signedContent, signatureCoversWholeDocument));
	
					} else if (isSignature(signatureDictionary)) {
						result.add(new PdfSignatureRevision(cms, signatureDictionary, dssDictionary, fieldNames, 
								validationCertPool, signedContent, signatureCoversWholeDocument));
	
					} else {
						LOG.warn("The entry {} is skipped. A signature dictionary entry with a type '{}' and subFilter '{}' is not acceptable configuration!",
								fieldNames, signatureDictionary.getType(), signatureDictionary.getSubFilter());
						
					}
					
				} catch (Exception e) {
					String errorMessage = "Unable to parse signature {} . Reason : {}";
					if (LOG.isDebugEnabled()) {
						LOG.error(errorMessage, fieldNames, e.getMessage(), e);
					} else {
						LOG.error(errorMessage, fieldNames, e.getMessage() );
					}
					
				}
			}

			linkSignatures(result);

		} catch (BadPasswordException e) {
			throw new InvalidPasswordException(e.getMessage());
		} catch (Exception e) {
			throw new DSSException("Cannot analyze signatures : " + e.getMessage(), e);
		}
		return result;
	}
	
	private Map<PdfSignatureDictionary, List<String>> extractSigDictionaries(AcroFields acroFields) {
		Map<PdfSignatureDictionary, List<String>> pdfDictionaries = new LinkedHashMap<>();
		Map<Integer, PdfSigDictWrapper> pdfObjectDictMap = new LinkedHashMap<>();
		
		Map<String, Item> allFields = acroFields.getAllFields();
		List<String> names = acroFields.getSignedFieldNames();
		LOG.info("{} signature field(s) found", names.size());
		// TODO : sort the fields ?
		
		for (String name : names) {
			PdfDictionary pdfField = allFields.get(name).getMerged(0);
			int refNumber = pdfField.getAsIndirectObject(PdfName.V).getNumber();
			PdfSigDictWrapper signature = pdfObjectDictMap.get(refNumber);
			if (signature == null) {
				PdfDict dictionary = new ITextPdfDict(pdfField.getAsDict(PdfName.V));
				signature = new PdfSigDictWrapper(dictionary);

				pdfDictionaries.put(signature, new ArrayList<>(Arrays.asList(name)));
				pdfObjectDictMap.put(refNumber, signature);
				
			} else {
				List<String> fieldNameList = pdfDictionaries.get(signature);
				fieldNameList.add(name);
				LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldNameList);
				
			}
		}
		
		return pdfDictionaries;
	}

	private PdfDssDict getDSSDictionary(PdfReader reader) {
		PdfDict currentCatalog = new ITextPdfDict(reader.getCatalog());
		return PdfDssDict.extract(currentCatalog);
	}

	private PdfDssDict getDSSDictionaryPresentInRevision(byte[] originalBytes) {
		try (PdfReader reader = new PdfReader(originalBytes)) {
			return getDSSDictionary(reader);
		} catch (Exception e) {
			LOG.warn("Cannot check in previous revisions if DSS dictionary already exist : " + e.getMessage(), e);
			return null;
		}
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is)) {

			PdfStamper stp = new PdfStamper(reader, baos, '\0', true);
			PdfWriter writer = stp.getWriter();

			if (Utils.isCollectionNotEmpty(callbacks)) {

				Map<String, Long> knownObjects = buildKnownObjects(callbacks);

				PdfDictionary catalog = reader.getCatalog();

				PdfDictionary dss = new PdfDictionary();
				PdfDictionary vrim = new PdfDictionary();
				PdfArray ocsps = new PdfArray();
				PdfArray crls = new PdfArray();
				PdfArray certs = new PdfArray();

				for (DSSDictionaryCallback callback : callbacks) {
					PdfArray ocsp = new PdfArray();
					PdfArray crl = new PdfArray();
					PdfArray cert = new PdfArray();
					PdfDictionary vri = new PdfDictionary();
					for (CRLToken crlToken : callback.getCrls()) {
						PdfObject iref = getPdfObjectForToken(crlToken, knownObjects, reader, writer);
						crl.add(iref);
						crls.add(iref);
					}
					for (OCSPToken ocspToken : callback.getOcsps()) {
						PdfObject iref = getPdfObjectForToken(ocspToken, knownObjects, reader, writer);
						ocsp.add(iref);
						ocsps.add(iref);
					}
					for (CertificateToken certToken : callback.getCertificates()) {
						PdfObject iref = getPdfObjectForToken(certToken, knownObjects, reader, writer);
						cert.add(iref);
						certs.add(iref);
					}
					if (ocsp.size() > 0) {
						vri.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_VRI), ocsp);
					}
					if (crl.size() > 0) {
						vri.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_VRI), crl);
					}
					if (cert.size() > 0) {
						vri.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_VRI), cert);
					}
					String vkey = callback.getSignature().getVRIKey();
					vrim.put(new PdfName(vkey), vri);
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
		String digest = getTokenDigest(token);
		Long objectNumber = knownObjects.get(digest);
		if (objectNumber == null) {
			PdfStream ps = new PdfStream(token.getEncoded());
			return writer.addToBody(ps, false).getIndirectReference();
		} else {
			return new PRIndirectReference(reader, objectNumber.intValue());
		}
	}

	@Override
	public List<String> getAvailableSignatureFields(DSSDocument document) {
		try (InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is, getPasswordBinary(passwordProtection))) {
			List<String> result = new ArrayList<>();
			AcroFields acroFields = reader.getAcroFields();
			List<String> names = acroFields.getSignedFieldNames();
			for (String name : names) {
				PdfDictionary dictionary = acroFields.getSignatureDictionary(name);
				if (dictionary == null) {
					result.add(name);
				}
			}
			return result;
		} catch (BadPasswordException e) {
			throw new InvalidPasswordException(e.getMessage());
		} catch (Exception e) {
			throw new DSSException(e);
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
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {

		checkDocumentPermissions(document);
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = document.openStream();
				PdfReader reader = new PdfReader(is)) {

			PdfStamper stp = new PdfStamper(reader, baos, '\0', true);

			stp.addSignature(parameters.getName(), parameters.getPage() + 1, parameters.getOriginX(),
					parameters.getOriginY(), parameters.getWidth(), parameters.getHeight());

			stp.close();

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add a signature field", e);
		}
	}

}
