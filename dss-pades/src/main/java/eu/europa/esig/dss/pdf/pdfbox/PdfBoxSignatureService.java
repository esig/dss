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

import java.awt.Dimension;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.DSSPDFUtils;
import eu.europa.esig.dss.pades.signature.visible.ImageFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.SignatureValidationCallback;
import eu.europa.esig.dss.pdf.model.ModelPdfDict;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

class PdfBoxSignatureService implements PDFSignatureService {

	private static final Logger logger = LoggerFactory.getLogger(PdfBoxSignatureService.class);

	@Override
	public byte[] digest(final InputStream toSignDocument, final PAdESSignatureParameters parameters, final DigestAlgorithm digestAlgorithm,
			final Map.Entry<String, ModelPdfDict>... extraDictionariesToAddBeforeSign) throws DSSException {

		final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
		File toSignFile = null;
		File signedFile = null;
		PDDocument pdDocument = null;
		try {

			toSignFile = DSSPDFUtils.getFileFromPdfData(toSignDocument);

			pdDocument = PDDocument.load(toSignFile);
			addExtraDictionaries(pdDocument, extraDictionariesToAddBeforeSign);
			PDSignature pdSignature = createSignatureDictionary(parameters);

			signedFile = File.createTempFile("sd-dss-", "-signed.pdf");
			final FileOutputStream fileOutputStream = DSSPDFUtils.getFileOutputStream(toSignFile, signedFile);

			final byte[] digestValue = signDocumentAndReturnDigest(parameters, signatureValue, signedFile, fileOutputStream, pdDocument, pdSignature,
					digestAlgorithm);
			return digestValue;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			DSSUtils.delete(toSignFile);
			DSSUtils.delete(signedFile);
			IOUtils.closeQuietly(pdDocument);
		}
	}

	@Override
	public void sign(final InputStream pdfData, final byte[] signatureValue, final OutputStream signedStream, final PAdESSignatureParameters parameters,
			final DigestAlgorithm digestAlgorithm, final Map.Entry<String, ModelPdfDict>... extraDictionariesToAddBeforeSign) throws DSSException {

		File toSignFile = null;
		File signedFile = null;
		FileInputStream fileInputStream = null;
		FileInputStream finalFileInputStream = null;
		PDDocument pdDocument = null;
		try {

			toSignFile = DSSPDFUtils.getFileFromPdfData(pdfData);

			pdDocument = PDDocument.load(toSignFile);
			addExtraDictionaries(pdDocument, extraDictionariesToAddBeforeSign);
			final PDSignature pdSignature = createSignatureDictionary(parameters);

			signedFile = File.createTempFile("sd-dss-", "-signed.pdf");
			final FileOutputStream fileOutputStream = DSSPDFUtils.getFileOutputStream(toSignFile, signedFile);

			signDocumentAndReturnDigest(parameters, signatureValue, signedFile, fileOutputStream, pdDocument, pdSignature, digestAlgorithm);

			finalFileInputStream = new FileInputStream(signedFile);
			IOUtils.copy(finalFileInputStream, signedStream);
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(fileInputStream);
			IOUtils.closeQuietly(finalFileInputStream);
			DSSUtils.delete(toSignFile);
			DSSUtils.delete(signedFile);
			IOUtils.closeQuietly(pdDocument);
		}
	}

	private byte[] signDocumentAndReturnDigest(final PAdESSignatureParameters parameters, final byte[] signatureBytes, final File signedFile,
			final FileOutputStream fileOutputStream, final PDDocument pdDocument, final PDSignature pdSignature, final DigestAlgorithm digestAlgorithm)
					throws DSSException {

		try {

			final MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
			// register signature dictionary and sign interface
			SignatureInterface signatureInterface = new SignatureInterface() {

				@Override
				public byte[] sign(InputStream content) throws SignatureException, IOException {
					byte[] b = new byte[4096];
					int count;
					while ((count = content.read(b)) > 0) {
						digest.update(b, 0, count);
					}
					return signatureBytes;
				}
			};

			SignatureOptions options = new SignatureOptions();
			options.setPreferedSignatureSize(parameters.getSignatureSize());

			if (parameters.getImageParameters() != null) {
				fillImageParameters(pdDocument, parameters.getImageParameters(), options);
			}
			pdDocument.addSignature(pdSignature, signatureInterface, options);

			saveDocumentIncrementally(parameters, signedFile, fileOutputStream, pdDocument);
			final byte[] digestValue = digest.digest();
			if (logger.isDebugEnabled()) {
				logger.debug("Digest to be signed: " + Hex.encodeHexString(digestValue));
			}
			fileOutputStream.close();
			return digestValue;
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (SignatureException e) {
			throw new DSSException(e);
		}
	}

	private void fillImageParameters(final PDDocument doc, final SignatureImageParameters imgParams, SignatureOptions options) throws IOException {
		Dimension optimalSize = ImageFactory.getOptimalSize(imgParams);
		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(doc, ImageFactory.create(imgParams), imgParams.getPage());
		visibleSig.xAxis(imgParams.getxAxis()).yAxis(imgParams.getyAxis()).width((float) optimalSize.getWidth()).height((float) optimalSize.getHeight());

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

		options.setVisualSignature(signatureProperties);
		options.setPage(imgParams.getPage());
	}

	private void addExtraDictionaries(final PDDocument doc, final Map.Entry<String, ModelPdfDict>[] extraDictionariesToAddBeforeSign) {

		final COSDictionary cosDictionary = doc.getDocumentCatalog().getCOSDictionary();
		for (final Map.Entry<String, ModelPdfDict> pdfDictEntry : extraDictionariesToAddBeforeSign) {

			final String key = pdfDictEntry.getKey();
			final PdfBoxDict value = new PdfBoxDict(pdfDictEntry.getValue());
			final COSDictionary wrapped = value.getWrapped();
			cosDictionary.setItem(key, wrapped);
		}
	}

	private PDSignature createSignatureDictionary(final PAdESSignatureParameters parameters) {

		final PDSignature signature = new PDSignature();
		signature.setType(getType());
		signature.setName(String.format("SD-DSS Signature %s", parameters.getDeterministicId()));
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// sub-filter for basic and PAdES Part 2 signatures
		signature.setSubFilter(getSubFilter());

		if (COSName.SIG.equals(getType())){
			if (StringUtils.isNotEmpty(parameters.getContactInfo())) {
				signature.setContactInfo(parameters.getContactInfo());
			}

			if (StringUtils.isNotEmpty(parameters.getLocation())) {
				signature.setLocation(parameters.getLocation());
			}

			if (StringUtils.isNotEmpty(parameters.getReason())) {
				signature.setReason(parameters.getReason());
			}
		}

		// the signing date, needed for valid signature
		final Calendar cal = Calendar.getInstance();
		final Date signingDate = parameters.bLevel().getSigningDate();
		cal.setTime(signingDate);
		signature.setSignDate(cal);
		return signature;
	}

	public static void saveDocumentIncrementally(PAdESSignatureParameters parameters, File signedFile, FileOutputStream fileOutputStream,
			PDDocument pdDocument) throws DSSException {

		FileInputStream signedFileInputStream = null;
		try {

			signedFileInputStream = new FileInputStream(signedFile);
			// the document needs to have an ID, if not a ID based on the current system time is used, and then the digest of the signed data is
			// different
			if (pdDocument.getDocumentId() == null) {

				final byte[] documentIdBytes = DSSUtils.digest(DigestAlgorithm.MD5, parameters.bLevel().getSigningDate().toString().getBytes());
				pdDocument.setDocumentId(DSSUtils.toLong(documentIdBytes));
				pdDocument.setDocumentId(0L);
			}
			pdDocument.saveIncremental(signedFileInputStream, fileOutputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (COSVisitorException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(signedFileInputStream);
		}
	}

	protected COSName getType() {
		return COSName.SIG;
	}

	protected COSName getSubFilter() {
		return PDSignature.SUBFILTER_ETSI_CADES_DETACHED;
	}

	@Override
	public void validateSignatures(CertificatePool validationCertPool, InputStream input, SignatureValidationCallback callback) throws DSSException {
		// recursive search of signature
		Map<String, Set<PdfSignatureOrDocTimestampInfo>> byteRangeMap = new HashMap<String, Set<PdfSignatureOrDocTimestampInfo>>();
		final Set<PdfSignatureOrDocTimestampInfo> signaturesFound = validateSignatures(validationCertPool, byteRangeMap, null, input);
		for (PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo : signaturesFound) {
			callback.validate(pdfSignatureOrDocTimestampInfo);
		}
	}

	/* This is O(scary), but seems quick enough in practice. */

	/**
	 * @param validationCertPool
	 * @param byteRangeMap
	 * @param outerCatalog
	 *            the PdfDictionary of the document that enclose the document stored in the input InputStream
	 * @param input
	 *            the Pdf bytes to open as a PDF
	 * @return
	 * @throws DSSException
	 */
	private Set<PdfSignatureOrDocTimestampInfo> validateSignatures(CertificatePool validationCertPool,
			Map<String, Set<PdfSignatureOrDocTimestampInfo>> byteRangeMap, PdfBoxDict outerCatalog, InputStream input) throws DSSException {

		Set<PdfSignatureOrDocTimestampInfo> signaturesFound = new LinkedHashSet<PdfSignatureOrDocTimestampInfo>();
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		PDDocument doc = null;
		try {

			IOUtils.copy(input, buffer);

			doc = PDDocument.load(new ByteArrayInputStream(buffer.toByteArray()));
			final PdfBoxDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSDictionary(), doc);

			final List<PDSignature> signatureDictionaries = doc.getSignatureDictionaries();
			if (logger.isDebugEnabled()) {
				logger.debug("Found {} signatures in PDF dictionary of PDF sized {} bytes", signatureDictionaries.size(), buffer.size());
			}
			for (int i = 0; i < signatureDictionaries.size(); i++) {

				final PDSignature signature = signatureDictionaries.get(i);
				/**
				 * SubFilter Name (Required) The value of SubFilter identifies the format of the data contained in the stream. A conforming reader may
				 * use any conforming signature handler that supports the specified format. When the value of Type is DocTimestamp, the value of
				 * SubFilter shall be ETSI.RFC3161.
				 */
				final String subFilter = signature.getSubFilter();
				if (StringUtils.isBlank(subFilter)) {

					logger.warn("No signature found in signature Dictionary:Content, SUB_FILTER is empty!");
					continue;
				}
				byte[] cms = new PdfBoxDict(signature.getDictionary(), doc).get("Contents");

				PdfSignatureOrDocTimestampInfo signatureInfo;
				try {
					if (PdfBoxDocTimeStampService.SUB_FILTER_ETSI_RFC3161.getName().equals(subFilter)) {
						signatureInfo = PdfSignatureFactory.createPdfTimestampInfo(validationCertPool, outerCatalog, doc, signature, cms, buffer);
					} else {
						signatureInfo = PdfSignatureFactory.createPdfSignatureInfo(validationCertPool, outerCatalog, doc, signature, cms, buffer);
					}
				} catch (PdfSignatureOrDocTimestampInfo.DSSPadesNoSignatureFound e) {
					logger.debug("No signature found in signature Dictionary:Content", e);
					continue;
				}

				signatureInfo = signatureAlreadyInListOrSelf(signaturesFound, signatureInfo);

				// should store in memory this byte range with a list of signature found there
				final String byteRange = Arrays.toString(signature.getByteRange());
				Set<PdfSignatureOrDocTimestampInfo> innerSignaturesFound = byteRangeMap.get(byteRange);
				if (innerSignaturesFound == null) {
					// Recursive call to find inner signatures in the byte range covered by this signature. Deep first search.
					final byte[] originalBytes = signatureInfo.getOriginalBytes();
					if (logger.isDebugEnabled()) {
						logger.debug("Searching signature in the previous revision of the document, size of revision is {} bytes", originalBytes.length);
					}
					innerSignaturesFound = validateSignatures(validationCertPool, byteRangeMap, catalog, new ByteArrayInputStream(originalBytes));
					byteRangeMap.put(byteRange, innerSignaturesFound);
				}

				// need to mark a signature as included inside another one. It's needed to link timestamp signature with the signatures covered by the
				// timestamp.
				for (PdfSignatureOrDocTimestampInfo innerSignature : innerSignaturesFound) {
					innerSignature = signatureAlreadyInListOrSelf(signaturesFound, innerSignature);
					signaturesFound.add(innerSignature);
					innerSignature.addOuterSignature(signatureInfo);
				}

				signaturesFound.add(signatureInfo);
			}
		} catch (IOException up) {
			logger.error("Error loading buffer of size {}", buffer.size(), up);
			// ignore error when loading signatures
		} finally {
			IOUtils.closeQuietly(doc);
		}
		return signaturesFound;
	}

	/**
	 * This method is needed because we will encounter many times the same signature during our document analysis. We make sure that we always add it
	 * only once.
	 *
	 * @param signaturesFound
	 * @param pdfSignatureOrDocTimestampInfo
	 * @return
	 */
	private PdfSignatureOrDocTimestampInfo signatureAlreadyInListOrSelf(Set<PdfSignatureOrDocTimestampInfo> signaturesFound,
			final PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo) {
		final int uniqueId = pdfSignatureOrDocTimestampInfo.uniqueId();
		for (final PdfSignatureOrDocTimestampInfo existingSignature : signaturesFound) {

			if (existingSignature.uniqueId() == uniqueId) {

				if (existingSignature instanceof PdfDocTimestampInfo) {

					final PdfDocTimestampInfo existingSignatureDocTimestamp = (PdfDocTimestampInfo) existingSignature;
					if (existingSignatureDocTimestamp.getTimestampToken().getTimeStampType() == TimestampType.SIGNATURE_TIMESTAMP) {

						if (logger.isDebugEnabled()) {
							logger.debug("Signature was already found in the external doc. Returning newly (inner) found signature {} {}",
									existingSignature.getClass().getSimpleName(), uniqueId);
						}
						return existingSignatureDocTimestamp;
					}
				}
				for (final PdfSignatureOrDocTimestampInfo outerSignature : existingSignature.getOuterSignatures()) {
					pdfSignatureOrDocTimestampInfo.addOuterSignature(outerSignature);
				}
				signaturesFound.remove(existingSignature);
				signaturesFound.add(pdfSignatureOrDocTimestampInfo);
				if (logger.isDebugEnabled()) {
					logger.debug("Signature was already found in the external doc. Returning newly (inner) found signature {} {}",
							pdfSignatureOrDocTimestampInfo.getClass().getSimpleName(), uniqueId);
				}
				return pdfSignatureOrDocTimestampInfo;
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("Signature newly found {} {}", pdfSignatureOrDocTimestampInfo.getClass().getSimpleName(), uniqueId);
		}
		return pdfSignatureOrDocTimestampInfo;
	}


}