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
package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.PAdESSignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.pdf.PDFTimestampService;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.signature.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.Token;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;
import eu.europa.ec.markt.dss.validation102853.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Extend a PAdES extension up to LTV.
 *
 *
 */

class PAdESLevelBaselineLT implements SignatureExtension<PAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBaselineLT.class);

	// DSSS/VRI dictionary is not mandatory, therefore it's not included
	private static final boolean INCLUDE_VRI_DICTIONARY = false;

	// the information read from the signatures
	final PdfObjFactory factory = PdfObjFactory.getInstance();
	private PdfArray certArray = factory.newArray();
	private PdfArray ocspArray = factory.newArray();
	private PdfArray crlArray = factory.newArray();

	private final CertificateVerifier certificateVerifier;
	private final TSPSource tspSource;

	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier) {

		this.certificateVerifier = certificateVerifier;
		this.tspSource = tspSource;
	}

	/**
	 * @param document
	 * @param parameters
	 * @return
	 * @throws IOException
	 */
	@Override
	public InMemoryDocument extendSignatures(DSSDocument document, final PAdESSignatureParameters parameters) throws DSSException {

		try {

			// check if needed to extends with PAdESLevelBaselineT
			final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
			pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
			List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
			for (final AdvancedSignature signature : signatures) {

				if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T)) {

					final PAdESLevelBaselineT padesLevelBaselineT = new PAdESLevelBaselineT(tspSource, certificateVerifier);
					document = padesLevelBaselineT.extendSignatures(document, parameters);
					final PDFDocumentValidator pdfDocumentValidatorOverTimestamp = new PDFDocumentValidator(document);
					pdfDocumentValidatorOverTimestamp.setCertificateVerifier(certificateVerifier);
					signatures = pdfDocumentValidator.getSignatures();
					break;
				}
			}

			assertExtendSignaturePossible(pdfDocumentValidator);

			for (final AdvancedSignature signature : signatures) {
				if (signature instanceof PAdESSignature) {
					PAdESSignature pAdESSignature = (PAdESSignature) signature;
					validate(pAdESSignature);
				}
			}

			final PdfDict dssDictionary = createDSSDictionary();

			/**
			 * Add the signature's VRI dictionary, hashing the signature block from the callback method.<br>
			 * The key of each entry in this dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature to
			 * which it applies and the value is the Signature VRI dictionary which contains the validation-related
			 * information for that signature.
			 */
			if (INCLUDE_VRI_DICTIONARY) {

				PdfDict vriDictionary = factory.newDict("VRI");
				for (final AdvancedSignature signature : signatures) {
					if (signature instanceof PAdESSignature) {
						PdfDict sigVriDictionary = factory.newDict();
						// sigVriDictionary to be completed with Cert, CRL and OCSP specific to this signature
						PAdESSignature pAdESSignature = (PAdESSignature) signature;

						final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pAdESSignature.getCAdESSignature().getCmsSignedData().getEncoded());
						String hexHash = Hex.encodeHexString(digest).toUpperCase();

						vriDictionary.add(hexHash, sigVriDictionary);

					}
				}

				dssDictionary.add("VRI", vriDictionary);
				// Cert, CRL and OCSP to be included
			}

			/*
             Baseline LT: "Hence implementations claiming conformance to the LT-Conformance Level build the PAdES-LTV form
             (PAdES Part 4 [9], clause 4) on signatures that shall be compliant to the T-Level requirements and to the present
             clause."

             LTA: "It is recommended that signed PDF documents, conforming to this profile, contain DSS followed by a document Time-stamp."

             So we add a timestamp, and that a good thing because PDFBox cannot do incremental update without signing.
			 */
			final ByteArrayOutputStream tDoc = new ByteArrayOutputStream();
			final PDFTimestampService timestampService = factory.newTimestampSignatureService();
			Map.Entry<String, PdfDict> dictToAdd = new AbstractMap.SimpleEntry<String, PdfDict>("DSS", dssDictionary);
			timestampService.timestamp(document, tDoc, parameters, tspSource, dictToAdd);
			final InMemoryDocument inMemoryDocument = new InMemoryDocument(tDoc.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private PdfDict createDSSDictionary() throws IOException {
		final PdfDict dssDictionary = factory.newDict("DSS");

		if (certArray.size() > 0) {
			dssDictionary.add("Certs", certArray);
		}

		if (crlArray.size() > 0) {
			dssDictionary.add("CRLs", crlArray);
		}

		if (ocspArray.size() > 0) {
			dssDictionary.add("OCSPs", ocspArray);
		}
		return dssDictionary;
	}

	private void assertExtendSignaturePossible(PDFDocumentValidator pdfDocumentValidator) {

	}

	private void validate(final PAdESSignature pAdESSignature) {

		final CAdESSignature cadesSignature = pAdESSignature.getCAdESSignature();
		final ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);
		final DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusionInProfileLT = cadesSignature.getRevocationDataForInclusion(validationContext);

		for (final CRLToken crlToken : revocationsForInclusionInProfileLT.crlTokens) {
			addNewToken(crlToken, crlArray);

		}
		for (final OCSPToken ocspToken : revocationsForInclusionInProfileLT.ocspTokens) {

			addNewToken(ocspToken, ocspArray);
		}
		final Set<CertificateToken> certificatesForInclusionInProfileLT = cadesSignature.getCertificatesForInclusion(validationContext);
		for (final CertificateToken certificateToken : certificatesForInclusionInProfileLT) {

			addNewToken(certificateToken, certArray);
		}
	}

	private void addNewToken(final Token crlToken, final PdfArray pdfArray) throws DSSException {

		try {

			final PdfStream stream = factory.newStream(crlToken.getEncoded());
			pdfArray.add(stream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
}
