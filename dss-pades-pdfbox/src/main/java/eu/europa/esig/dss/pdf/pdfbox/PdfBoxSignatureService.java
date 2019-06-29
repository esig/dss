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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

public class PdfBoxSignatureService extends AbstractPDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxSignatureService.class);

	/**
	 * Constructor for the PdfBoxSignatureService
	 * 
	 * @param timestamp
	 *                  if true, the instance is used to generate DocumentTypestamp
	 *                  if false, it is used to generate a signature layer
	 */
	public PdfBoxSignatureService(boolean timestamp, PdfBoxSignatureDrawerFactory signatureDrawerFactory) {
		super(timestamp, signatureDrawerFactory);
	}

	@Override
	public byte[] digest(final DSSDocument toSignDocument, final PAdESSignatureParameters parameters, final DigestAlgorithm digestAlgorithm) {

		final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				InputStream is = toSignDocument.openStream();
				PDDocument pdDocument = PDDocument.load(is)) {
			final byte[] digest = signDocumentAndReturnDigest(parameters, signatureValue, outputStream, pdDocument, digestAlgorithm);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Base64 messageDigest : {}", Utils.toBase64(digest));
			}
			return digest;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument sign(final DSSDocument toSignDocument, final byte[] signatureValue, final PAdESSignatureParameters parameters,
			final DigestAlgorithm digestAlgorithm) {

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				InputStream is = toSignDocument.openStream();
				PDDocument pdDocument = PDDocument.load(is)) {

			signDocumentAndReturnDigest(parameters, signatureValue, baos, pdDocument, digestAlgorithm);

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private byte[] signDocumentAndReturnDigest(final PAdESSignatureParameters parameters, final byte[] signatureBytes, final OutputStream fileOutputStream,
			final PDDocument pdDocument, final DigestAlgorithm digestAlgorithm) {

		final MessageDigest digest = digestAlgorithm.getMessageDigest();
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

		final PDSignature pdSignature = createSignatureDictionary(parameters, pdDocument);
		try (SignatureOptions options = new SignatureOptions()) {
			options.setPreferredSignatureSize(parameters.getSignatureSize());

			SignatureImageParameters imageParameters = getImageParameters(parameters);
			if (imageParameters != null && signatureDrawerFactory != null) {
				PdfBoxSignatureDrawer signatureDrawer = (PdfBoxSignatureDrawer) signatureDrawerFactory.getSignatureDrawer(imageParameters);
				signatureDrawer.init(imageParameters, pdDocument, options);
				signatureDrawer.draw();
			}

			pdDocument.addSignature(pdSignature, signatureInterface, options);

			saveDocumentIncrementally(parameters, fileOutputStream, pdDocument);
			return digest.digest();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private PDSignature createSignatureDictionary(final PAdESSignatureParameters parameters, PDDocument pdDocument) {

		PDSignature signature;
		if (!timestamp && Utils.isStringNotEmpty(parameters.getSignatureFieldId())) {
			signature = findExistingSignature(pdDocument, parameters.getSignatureFieldId());
		} else {
			signature = new PDSignature();
		}

		COSName currentType = COSName.getPDFName(getType());
		signature.setType(currentType);
		signature.setFilter(COSName.getPDFName(getFilter(parameters)));
		// sub-filter for basic and PAdES Part 2 signatures
		signature.setSubFilter(COSName.getPDFName(getSubFilter(parameters)));

		if (COSName.SIG.equals(currentType)) {

			signature.setName(getSignatureName(parameters));

			if (Utils.isStringNotEmpty(parameters.getContactInfo())) {
				signature.setContactInfo(parameters.getContactInfo());
			}

			if (Utils.isStringNotEmpty(parameters.getLocation())) {
				signature.setLocation(parameters.getLocation());
			}

			if (Utils.isStringNotEmpty(parameters.getReason())) {
				signature.setReason(parameters.getReason());
			}

			CertificationPermission permission = parameters.getPermission();
			// A document can contain only one signature field that contains a DocMDP
			// transform method;
			// it shall be the first signed field in the document.
			if (permission != null && !containsFilledSignature(pdDocument)) {
				setMDPPermission(pdDocument, signature, permission.getCode());
			}

			// the signing date, needed for valid signature
			final Calendar cal = Calendar.getInstance();
			final Date signingDate = parameters.bLevel().getSigningDate();
			cal.setTime(signingDate);
			signature.setSignDate(cal);
		}

		return signature;
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
	 * @param doc
	 *                          The document.
	 * @param signature
	 *                          The signature object.
	 * @param accessPermissions
	 *                          The permission value (1, 2 or 3).
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

	private PDSignature findExistingSignature(PDDocument doc, String sigFieldName) {
		PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm();
		if (acroForm != null) {
			PDSignatureField signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
			if (signatureField != null) {
				PDSignature signature = signatureField.getSignature();
				if (signature == null) {
					signature = new PDSignature();
					signatureField.getCOSObject().setItem(COSName.V, signature);
					return signature;
				} else {
					throw new DSSException("The signature field '" + sigFieldName + "' can not be signed since its already signed.");
				}
			}
		}
		throw new DSSException("The signature field '" + sigFieldName + "' does not exist.");
	}

	public void saveDocumentIncrementally(PAdESSignatureParameters parameters, OutputStream outputStream, PDDocument pdDocument) throws DSSException {
		try {
			// the document needs to have an ID, if not a ID based on the current system
			// time is used, and then the
			// digest of the signed data is different
			if (pdDocument.getDocumentId() == null) {
				pdDocument.setDocumentId(parameters.bLevel().getSigningDate().getTime());
			}
			pdDocument.saveIncremental(outputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	protected List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool, DSSDocument document) {
		List<PdfSignatureOrDocTimestampInfo> signatures = new ArrayList<PdfSignatureOrDocTimestampInfo>();
		try (InputStream is = document.openStream(); PDDocument doc = PDDocument.load(is)) {

			byte[] originalBytes = DSSUtils.toByteArray(document);
			int originalBytesLength = originalBytes.length;

			PdfDssDict dssDictionary = getDSSDictionary(doc);

			List<PDSignature> pdSignatures = doc.getSignatureDictionaries();

			if (Utils.isCollectionNotEmpty(pdSignatures)) {
				LOG.debug("{} signature(s) found", pdSignatures.size());

				for (PDSignature signature : pdSignatures) {
					try {
						PdfDict dictionary = new PdfBoxDict(signature.getCOSObject(), doc);
						PdfSigDict signatureDictionary = new PdfSigDict(dictionary);
						final int[] byteRange = signatureDictionary.getByteRange();

						validateByteRange(byteRange);

						final byte[] cms = signatureDictionary.getContents();
						if (!isContentValueEqualsByteRangeExtraction(cms, signature, originalBytes)) {
							LOG.warn("Conflict between /Content and ByteRange for Signature '{}'.", signature.getName());
						}

						byte[] signedContent = signature.getSignedContent(originalBytes);

						// /ByteRange [0 575649 632483 10206]
						int beforeSignatureLength = byteRange[1] - byteRange[0];
						int expectedCMSLength = byteRange[2] - byteRange[1];
						int afterSignatureLength = byteRange[3];
						int totalCoveredByByteRange = beforeSignatureLength + expectedCMSLength + afterSignatureLength;

						boolean coverAllOriginalBytes = (originalBytesLength == totalCoveredByByteRange);

						PdfSignatureOrDocTimestampInfo signatureInfo = null;
						final String subFilter = signatureDictionary.getSubFilter();
						if (PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter)) {
							boolean isArchiveTimestamp = false;

							// LT or LTA
							if (dssDictionary != null) {
								// check is DSS dictionary already exist
								if (isDSSDictionaryPresentInPreviousRevision(getOriginalBytes(byteRange, signedContent))) {
									isArchiveTimestamp = true;
								}
							}

							signatureInfo = new PdfDocTimestampInfo(validationCertPool, signatureDictionary, dssDictionary, cms, signedContent,
									coverAllOriginalBytes, isArchiveTimestamp);
						} else {
							signatureInfo = new PdfSignatureInfo(validationCertPool, signatureDictionary, dssDictionary, cms, signedContent,
									coverAllOriginalBytes);
						}

						if (signatureInfo != null) {
							signatures.add(signatureInfo);
						}
					} catch (Exception e) {
						LOG.error("Unable to parse signature '" + signature.getName() + "' : ", e);
					}
				}
				linkSignatures(signatures);
			}
		} catch (Exception e) {
			throw new DSSException("Cannot analyze signatures : " + e.getMessage(), e);
		}

		return signatures;
	}

	private boolean isContentValueEqualsByteRangeExtraction(byte[] cms, PDSignature signature, byte[] originalBytes) {
		try {
			byte[] cmsWithByteRange = signature.getContents(originalBytes);
			return Arrays.equals(cms, cmsWithByteRange);
		} catch (Exception e) {
			String message = String.format("Unable to retrieve data from the ByteRange (signature name: %s)", signature.getName());
			if (LOG.isDebugEnabled()) {
				// Exception displays the (long) hex value
				LOG.debug(message, e);
			} else {
				LOG.error(message);
			}
			return false;
		}
	}

	private boolean isDSSDictionaryPresentInPreviousRevision(byte[] originalBytes) {
		try (PDDocument doc = PDDocument.load(originalBytes)) {
			return getDSSDictionary(doc) != null;
		} catch (Exception e) {
			LOG.warn("Cannot check in previous revisions if DSS dictionary already exist : " + e.getMessage(), e);
			return false;
		}
	}

	private PdfDssDict getDSSDictionary(PDDocument doc) {
		PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSObject(), doc);
		return PdfDssDict.extract(catalog);
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream is = document.openStream(); PDDocument pdDocument = PDDocument.load(is)) {

			if (Utils.isCollectionNotEmpty(callbacks)) {
				final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSObject();
				cosDictionary.setItem(PAdESConstants.DSS_DICTIONARY_NAME, buildDSSDictionary(pdDocument, callbacks));
				cosDictionary.setNeedToBeUpdated(true);
			}

			pdDocument.saveIncremental(baos);

			DSSDocument inMemoryDocument = new InMemoryDocument(baos.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;

		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private COSDictionary buildDSSDictionary(PDDocument pdDocument, List<DSSDictionaryCallback> callbacks) throws IOException {
		COSDictionary dss = new COSDictionary();

		Map<String, Long> knownObjects = buildKnownObjects(callbacks);

		Map<String, COSStream> streams = new HashMap<String, COSStream>();

		Set<CRLToken> allCrls = new HashSet<CRLToken>();
		Set<OCSPToken> allOcsps = new HashSet<OCSPToken>();
		Set<CertificateToken> allCertificates = new HashSet<CertificateToken>();

		COSDictionary vriDictionary = new COSDictionary();
		for (DSSDictionaryCallback callback : callbacks) {
			COSDictionary sigVriDictionary = new COSDictionary();
			sigVriDictionary.setDirect(true);

			Set<CertificateToken> currentCerts = callback.getCertificates();
			if (Utils.isCollectionNotEmpty(currentCerts)) {
				allCertificates.addAll(currentCerts);
				sigVriDictionary.setItem(PAdESConstants.CERT_ARRAY_NAME_VRI, buildArray(pdDocument, streams, currentCerts, knownObjects));
			}

			List<OCSPToken> currentOcsps = callback.getOcsps();
			if (Utils.isCollectionNotEmpty(currentOcsps)) {
				allOcsps.addAll(currentOcsps);
				sigVriDictionary.setItem(PAdESConstants.OCSP_ARRAY_NAME_VRI, buildArray(pdDocument, streams, currentOcsps, knownObjects));
			}

			List<CRLToken> currentCrls = callback.getCrls();
			if (Utils.isCollectionNotEmpty(currentCrls)) {
				allCrls.addAll(currentCrls);
				sigVriDictionary.setItem(PAdESConstants.CRL_ARRAY_NAME_VRI, buildArray(pdDocument, streams, currentCrls, knownObjects));
			}

			// We can't use CMSSignedData, the pdSignature content is trimmed (000000)
			PdfSignatureInfo pdfSignatureInfo = callback.getSignature().getPdfSignatureInfo();
			final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pdfSignatureInfo.getContent());
			String hexHash = Utils.toHex(digest).toUpperCase();

			vriDictionary.setItem(hexHash, sigVriDictionary);
		}
		dss.setItem(PAdESConstants.VRI_DICTIONARY_NAME, vriDictionary);

		if (Utils.isCollectionNotEmpty(allCertificates)) {
			dss.setItem(PAdESConstants.CERT_ARRAY_NAME_DSS, buildArray(pdDocument, streams, allCertificates, knownObjects));
		}

		if (Utils.isCollectionNotEmpty(allOcsps)) {
			dss.setItem(PAdESConstants.OCSP_ARRAY_NAME_DSS, buildArray(pdDocument, streams, allOcsps, knownObjects));
		}

		if (Utils.isCollectionNotEmpty(allCrls)) {
			dss.setItem(PAdESConstants.CRL_ARRAY_NAME_DSS, buildArray(pdDocument, streams, allCrls, knownObjects));
		}

		return dss;
	}

	private COSArray buildArray(PDDocument pdDocument, Map<String, COSStream> streams, Collection<? extends Token> tokens, Map<String, Long> knownObjects)
			throws IOException {
		COSArray array = new COSArray();
		// avoid duplicate CRLs
		List<String> currentObjIds = new ArrayList<String>();
		for (Token token : tokens) {
			String digest = getTokenDigest(token);
			if (!currentObjIds.contains(digest)) {
				Long objectNumber = knownObjects.get(digest);
				if (objectNumber == null ) {
					COSStream stream = streams.get(digest);
					if (stream == null) {
						stream = pdDocument.getDocument().createCOSStream();
						try (OutputStream unfilteredStream = stream.createOutputStream()) {
							unfilteredStream.write(token.getEncoded());
							unfilteredStream.flush();
						}
						streams.put(digest, stream);
					}
					array.add(stream);
				} else {
					List<COSObject> objects = pdDocument.getDocument().getObjects();
					COSObject foundCosObject = null;
					for (COSObject cosObject : objects) {
						if (cosObject.getObjectNumber() == objectNumber) {
							foundCosObject = cosObject;
							break;
						}
					}
					array.add(foundCosObject);
				}
				currentObjIds.add(digest);
			}
		}
		return array;
	}

	@Override
	public List<String> getAvailableSignatureFields(DSSDocument document) {
		List<String> result = new ArrayList<String>();
		try (InputStream is = document.openStream(); PDDocument pdfDoc = PDDocument.load(is)) {
			List<PDSignatureField> signatureFields = pdfDoc.getSignatureFields();
			for (PDSignatureField pdSignatureField : signatureFields) {
				PDSignature signature = pdSignatureField.getSignature();
				if (signature == null) {
					result.add(pdSignatureField.getPartialName());
				}
			}
		} catch (Exception e) {
			throw new DSSException("Unable to determine signature fields", e);
		}
		return result;
	}

	@Override
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
		DSSDocument newPdfDoc = null;
		try (InputStream is = document.openStream(); PDDocument pdfDoc = PDDocument.load(is);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			PDPage page = pdfDoc.getPage(parameters.getPage());
			
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
			if (Utils.isStringNotBlank(parameters.getName())) {
				signatureField.setPartialName(parameters.getName());
			}
			
			PDAnnotationWidget widget = signatureField.getWidgets().get(0);
			PDRectangle rect = new PDRectangle(parameters.getOriginX(), parameters.getOriginY(), parameters.getWidth(), parameters.getHeight());
			widget.setRectangle(rect);
			widget.setPage(page);
			page.getAnnotations().add(widget);
			
			acroForm.getFields().add(signatureField);

			acroForm.getCOSObject().setNeedToBeUpdated(true);
			signatureField.getCOSObject().setNeedToBeUpdated(true);
			page.getCOSObject().setNeedToBeUpdated(true);
			
			pdfDoc.saveIncremental(baos);
			
			newPdfDoc = new InMemoryDocument(baos.toByteArray(), "new-document.pdf", MimeType.PDF);
			
		} catch (Exception e) {
			throw new DSSException("Unable to add a new signature fields", e);
		}
		return newPdfDoc;
	}

}
