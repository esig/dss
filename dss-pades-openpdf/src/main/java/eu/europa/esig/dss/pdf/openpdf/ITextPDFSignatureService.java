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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.ByteBuffer;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.SignatureValidationCallback;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;

/**
 * Implementation of PDFSignatureService using iText
 *
 */
class ITextPDFSignatureService implements PDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPDFSignatureService.class);

	private int signatureSize = 12000;

	ITextPDFSignatureService() {
	}

	/**
	 * @param signatureSize
	 *                      the signatureSize to set
	 */
	public void setSignatureSize(int signatureSize) {
		this.signatureSize = signatureSize;
	}

	/**
	 * @return the signatureSize
	 */
	public int getSignatureSize() {
		return signatureSize;
	}

	protected String getType() {
		return SIGNATURE_TYPE;
	}

	protected String getFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getSignatureFilter())) {
			return parameters.getSignatureFilter();
		}
		return SIGNATURE_DEFAULT_FILTER;
	}

	protected String getSubFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getSignatureSubFilter())) {
			return parameters.getSignatureSubFilter();
		}
		return SIGNATURE_DEFAULT_SUBFILTER;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PdfStamper prepareStamper(InputStream pdfData, OutputStream output, PAdESSignatureParameters parameters) throws IOException, DocumentException {

		PdfReader reader = new PdfReader(pdfData);
		PdfStamper stp = PdfStamper.createSignature(reader, output, '\0', null, true);
		stp.setIncludeFileID(true);
		stp.setOverrideFileId(generateFileId(parameters));

		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		sap.setAcro6Layers(true);
		sap.setRender(PdfSignatureAppearance.SignatureRenderDescription);

		if (parameters.getSignatureImageParameters() != null) {

			/*
			 * Rectangle rect = new Rectangle(parameters.getRepresentation().getImageX(),
			 * parameters.getRepresentation().getImageY(),
			 * parameters.getRepresentation().getImageX() +
			 * parameters.getRepresentation().getImageWidth(),
			 * parameters.getRepresentation().getImageY() +
			 * parameters.getRepresentation().getImageHeight());
			 * sap.setVisibleSignature(rect, parameters.getRepresentation().getPage(),
			 * null);
			 * 
			 * Image image = Image.getInstance(parameters.getRepresentation().getImage());
			 * sap.setImage(image);
			 */
		}

		PdfSignature dic = new PdfSignature(new PdfName(getFilter(parameters)), new PdfName(getSubFilter(parameters)));
		PdfName type = new PdfName(getType());
		dic.put(PdfName.TYPE, type);

		if (PdfName.SIG.equals(type)) {

			dic.setName(PAdESUtils.getSignatureName(parameters));

			if (parameters.getReason() != null) {
				dic.setReason(parameters.getReason());
			}
			if (parameters.getLocation() != null) {
				dic.setLocation(parameters.getLocation());
			}
			if (parameters.getContactInfo() != null) {
				dic.setContact(parameters.getContactInfo());
			}

			Calendar cal = Calendar.getInstance();
			cal.setTime(parameters.bLevel().getSigningDate());
			sap.setSignDate(cal);
			dic.setDate(new PdfDate(cal));
		}

		sap.setCryptoDictionary(dic);

		int csize = getSignatureSize();
		HashMap exc = new HashMap();
		exc.put(PdfName.CONTENTS, new Integer((csize * 2) + 2));

		sap.preClose(exc);

		return stp;
	}

	private PdfObject generateFileId(PAdESSignatureParameters parameters) {
		try (ByteBuffer buf = new ByteBuffer(90)) {
			String deterministicId = parameters.getDeterministicId();
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
	public byte[] digest(DSSDocument toSignDocument, PAdESSignatureParameters parameters, DigestAlgorithm digestAlgorithm) throws DSSException {
		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			return DSSUtils.digest(digestAlgorithm, sap.getRangeStream());
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument sign(DSSDocument toSignDocument, byte[] signatureValue, PAdESSignatureParameters parameters, DigestAlgorithm digestAlgorithm)
			throws DSSException {

		try (InputStream is = toSignDocument.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			PdfStamper stp = prepareStamper(is, baos, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			byte[] pk = signatureValue;

			int csize = getSignatureSize();
			byte[] outc = new byte[csize];

			PdfDictionary dic = new PdfDictionary();

			System.arraycopy(pk, 0, outc, 0, pk.length);

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
	public void validateSignatures(CertificatePool pool, DSSDocument document, SignatureValidationCallback callback) throws DSSException {
		LOG.info("#### Start Signatures validations for document ");
		validateSignatures(pool, document, null, callback, new ArrayList<String>());
		LOG.info("#### End Signatures validations for document ");
	}

	@SuppressWarnings("unchecked")
	private void validateSignatures(CertificatePool pool, DSSDocument dssDocument, PdfDict outerCatalog, SignatureValidationCallback callback,
			List<String> alreadyLoadedRevisions) throws DSSException {
		try (InputStream is = dssDocument.openStream(); PdfReader reader = new PdfReader(is)) {
			AcroFields af = reader.getAcroFields();

			PdfDict currentCatalog = new ITextPdfDict(reader.getCatalog());
			PdfDssDict dssDictionary = PdfDssDict.extract(currentCatalog);
			/*
			 * Search the whole document of a signature
			 */
			List<String> names = af.getSignatureNames();

			LOG.info(names.size() + " signature(s)");
			// For every signature :
			for (String name : names) {

				LOG.info("Signature name: " + name);
				LOG.info("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
				LOG.info("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

				/*
				 * We are only interested in the validation of signature that covers the whole
				 * document.
				 */
				if (af.signatureCoversWholeDocument(name)) {

					PdfDict dictionary = new ITextPdfDict(af.getSignatureDictionary(name));
					PdfSigDict signatureDictionary = new PdfSigDict(dictionary);

					String revisionName = Integer.toString(af.getRevision(name));

					if (!alreadyLoadedRevisions.contains(revisionName)) {

						final byte[] cms = signatureDictionary.getContents();
						int[] byteRange = signatureDictionary.getByteRange();
						final byte[] signedContent = getSignedContent(dssDocument, byteRange);

						PdfSignatureInfo info = new PdfSignatureInfo(pool, signatureDictionary, dssDictionary, cms, signedContent, true);

						callback.validate(info);
						alreadyLoadedRevisions.add(revisionName);
					} else {
						LOG.info("Signature " + name + " was already covered");
					}

				} else {

					PdfDict catalog = new ITextPdfDict(reader.getCatalog());

					/*
					 * We open the version of the document that was protected by the signature
					 */
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					InputStream ip = af.extractRevision(name);
					IOUtils.copy(ip, out);
					out.close();
					ip.close();

					/*
					 * You can sign a PDF document with only one signature. So when we want multiple
					 * signature, signatures are appended sequentially to the end of the document.
					 * The recursive call help to get the signature from the original document.
					 */
					validateSignatures(pool, new InMemoryDocument(out.toByteArray()), catalog, callback, alreadyLoadedRevisions);

				}
			}

		} catch (RuntimeException e) {
			LOG.error(e.getMessage(), e);
			throw e;
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException(e);
		}

	}

	private byte[] getSignedContent(DSSDocument dssDocument, int[] byteRange) {

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream is = dssDocument.openStream()) {
			// Adobe Digital Signatures in a PDF (p5): In Figure 4, the hash is calculated
			// for bytes 0 through 839, and 960 through 1200. [0, 840, 960, 1200]

			int begining = byteRange[0];
			int startSigValueContent = byteRange[1] - 1;
			int endSigValueContent = byteRange[2];
			int end = endSigValueContent + byteRange[3];

			int counter = 0;
			int b;
			while ((b = is.read()) != -1) {
				if (((counter >= begining) && (counter <= startSigValueContent)) || ((counter >= endSigValueContent) && (counter <= end))) {
					baos.write(b);
				}
				counter++;
			}

			byte[] byteArray = baos.toByteArray();
			try (FileOutputStream fos = new FileOutputStream(new File("target/signedContent.pdf"))) {
				Utils.write(byteArray, fos);
			}
			return byteArray;

		} catch (IOException e) {
			throw new DSSException("Unable to extract the signed data", e);
		}
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) throws DSSException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<String> getAvailableSignatureFields(DSSDocument document) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
		// TODO Auto-generated method stub
		return null;
	}
}
