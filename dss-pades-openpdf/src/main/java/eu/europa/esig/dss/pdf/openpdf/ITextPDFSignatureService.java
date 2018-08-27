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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.ByteBuffer;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfoComparator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * Implementation of PDFSignatureService using iText
 *
 */
class ITextPDFSignatureService extends AbstractPDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPDFSignatureService.class);

	ITextPDFSignatureService() {
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

		Calendar cal = Calendar.getInstance();
		cal.setTime(parameters.bLevel().getSigningDate());

		stp.setEnforcedModificationDate(cal);

		if (PdfName.SIG.equals(type)) {

			dic.setName(getSignatureName(parameters));

			if (parameters.getReason() != null) {
				dic.setReason(parameters.getReason());
			}
			if (parameters.getLocation() != null) {
				dic.setLocation(parameters.getLocation());
			}
			if (parameters.getContactInfo() != null) {
				dic.setContact(parameters.getContactInfo());
			}

			sap.setSignDate(cal);
			dic.setDate(new PdfDate(cal));

		}

		sap.setCryptoDictionary(dic);

		int csize = parameters.getSignatureSize();
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

			int csize = parameters.getSignatureSize();
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
	@SuppressWarnings({ "unchecked" })
	protected List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool, DSSDocument document) {
		List<PdfSignatureOrDocTimestampInfo> result = new ArrayList<PdfSignatureOrDocTimestampInfo>();
		try (InputStream is = document.openStream(); PdfReader reader = new PdfReader(is)) {
			AcroFields af = reader.getAcroFields();
			List<String> names = af.getSignatureNames();

			PdfDssDict dssDictionary = getDSSDictionary(reader);

			LOG.info(names.size() + " signature(s)");
			for (String name : names) {
				try {
					LOG.info("Signature name: " + name);
					LOG.info("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

					PdfDict dictionary = new ITextPdfDict(af.getSignatureDictionary(name));
					PdfSigDict signatureDictionary = new PdfSigDict(dictionary);

					final byte[] cms = signatureDictionary.getContents();
					final int[] byteRange = signatureDictionary.getByteRange();
					final byte[] signedContent = getSignedContent(document, byteRange);
					boolean signatureCoversWholeDocument = af.signatureCoversWholeDocument(name);

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

						result.add(new PdfDocTimestampInfo(validationCertPool, signatureDictionary, dssDictionary, cms, signedContent,
								signatureCoversWholeDocument, isArchiveTimestamp));
					} else {
						result.add(
								new PdfSignatureInfo(validationCertPool, signatureDictionary, dssDictionary, cms, signedContent, signatureCoversWholeDocument));
					}

				} catch (IOException e) {
					LOG.error("Unable to parse signature '" + name + "' : ", e);
				}
			}

			Collections.sort(result, new PdfSignatureOrDocTimestampInfoComparator());
			linkSignatures(result);

		} catch (IOException e) {
			throw new DSSException("Unable to analyze document", e);
		}
		return result;
	}

	private PdfDssDict getDSSDictionary(PdfReader reader) {
		PdfDict currentCatalog = new ITextPdfDict(reader.getCatalog());
		return PdfDssDict.extract(currentCatalog);
	}

	private boolean isDSSDictionaryPresentInPreviousRevision(byte[] originalBytes) {
		try (PdfReader reader = new PdfReader(originalBytes)) {
			return getDSSDictionary(reader) != null;
		} catch (Exception e) {
			LOG.warn("Cannot check in previous revisions if DSS dictionary already exist : " + e.getMessage(), e);
			return false;
		}
	}

	private byte[] getSignedContent(DSSDocument dssDocument, int[] byteRange) throws IOException {

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream is = new BufferedInputStream(dssDocument.openStream())) {
			// Adobe Digital Signatures in a PDF (p5): In Figure 4, the hash is calculated
			// for bytes 0 through 839, and 960 through 1200. [0, 840, 960, 1200]

			int begining = byteRange[0];
			int startSigValueContent = byteRange[1];
			int endSigValueContent = byteRange[2];
			int end = endSigValueContent + byteRange[3];

			int counter = 0;
			int b;
			while ((b = is.read()) != -1) {
				if (((counter >= begining) && (counter < startSigValueContent)) || ((counter >= endSigValueContent) && (counter < end))) {
					baos.write(b);
				}
				counter++;
			}

			return baos.toByteArray();
		}
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) throws DSSException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); InputStream is = document.openStream(); PdfReader reader = new PdfReader(is)) {

			PdfStamper stp = new PdfStamper(reader, baos, '\0', true);
			PdfWriter writer = stp.getWriter();

			if (Utils.isCollectionNotEmpty(callbacks)) {
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
						PdfStream ps = new PdfStream(crlToken.getEncoded());
						ps.flateCompress();
						PdfIndirectReference iref = writer.addToBody(ps, false).getIndirectReference();
						crl.add(iref);
						crls.add(iref);
					}
					for (OCSPToken ocspToken : callback.getOcsps()) {
						PdfStream ps = new PdfStream(ocspToken.getEncoded());
						ps.flateCompress();
						PdfIndirectReference iref = writer.addToBody(ps, false).getIndirectReference();
						ocsp.add(iref);
						ocsps.add(iref);
					}
					for (CertificateToken certToken : callback.getCertificates()) {
						PdfStream ps = new PdfStream(certToken.getEncoded());
						ps.flateCompress();
						PdfIndirectReference iref = writer.addToBody(ps, false).getIndirectReference();
						cert.add(iref);
						certs.add(iref);
					}
					if (ocsp.size() > 0) {
						vri.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_VRI), writer.addToBody(ocsp, false).getIndirectReference());
					}
					if (crl.size() > 0) {
						vri.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_VRI), writer.addToBody(crl, false).getIndirectReference());
					}
					if (cert.size() > 0) {
						vri.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_VRI), writer.addToBody(cert, false).getIndirectReference());
					}
					String vkey = getVRIKey(callback.getSignature());
					vrim.put(new PdfName(vkey), writer.addToBody(vri, false).getIndirectReference());
				}
				dss.put(new PdfName(PAdESConstants.VRI_DICTIONARY_NAME), writer.addToBody(vrim, false).getIndirectReference());
				if (ocsps.size() > 0) {
					dss.put(new PdfName(PAdESConstants.OCSP_ARRAY_NAME_DSS), writer.addToBody(ocsps, false).getIndirectReference());
				}
				if (crls.size() > 0) {
					dss.put(new PdfName(PAdESConstants.CRL_ARRAY_NAME_DSS), writer.addToBody(crls, false).getIndirectReference());
				}
				if (certs.size() > 0) {
					dss.put(new PdfName(PAdESConstants.CERT_ARRAY_NAME_DSS), writer.addToBody(certs, false).getIndirectReference());
				}
				catalog.put(new PdfName(PAdESConstants.DSS_DICTIONARY_NAME), writer.addToBody(dss, false).getIndirectReference());

				stp.getWriter().addToBody(reader.getCatalog(), reader.getCatalog().getIndRef(), false);
			}

			stp.close();
			baos.close();

			DSSDocument signature = new InMemoryDocument(baos.toByteArray());
			signature.setMimeType(MimeType.PDF);
			return signature;
		} catch (IOException e) {
			throw new DSSException("Unable to add DSS dictionary", e);
		}
	}

	private String getVRIKey(PAdESSignature signature) {
		PdfSignatureInfo pdfSignatureInfo = signature.getPdfSignatureInfo();
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pdfSignatureInfo.getContent());
		return Utils.toHex(digest).toUpperCase();
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
