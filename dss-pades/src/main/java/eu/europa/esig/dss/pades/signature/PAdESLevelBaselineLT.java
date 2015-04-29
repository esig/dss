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
package eu.europa.esig.dss.pades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.model.ModelPdfArray;
import eu.europa.esig.dss.pdf.model.ModelPdfDict;
import eu.europa.esig.dss.pdf.model.ModelPdfStream;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;

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
	private ModelPdfArray certArray = new ModelPdfArray();
	private ModelPdfArray ocspArray = new ModelPdfArray();
	private ModelPdfArray crlArray = new ModelPdfArray();

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

			final ModelPdfDict dssDictionary = createDSSDictionary();

			/**
			 * Add the signature's VRI dictionary, hashing the signature block from the callback method.<br>
			 * The key of each entry in this dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature to
			 * which it applies and the value is the Signature VRI dictionary which contains the validation-related
			 * information for that signature.
			 */
			if (INCLUDE_VRI_DICTIONARY) {

				ModelPdfDict vriDictionary = new ModelPdfDict("VRI");
				for (final AdvancedSignature signature : signatures) {
					if (signature instanceof PAdESSignature) {
						ModelPdfDict sigVriDictionary = new ModelPdfDict();
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
			final PDFTimestampService timestampService = PdfObjFactory.getInstance().newTimestampSignatureService();
			Map.Entry<String, ModelPdfDict> dictToAdd = new AbstractMap.SimpleEntry<String, ModelPdfDict>("DSS", dssDictionary);
			timestampService.timestamp(document, tDoc, parameters, tspSource, dictToAdd);
			final InMemoryDocument inMemoryDocument = new InMemoryDocument(tDoc.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private ModelPdfDict createDSSDictionary() throws IOException {
		final ModelPdfDict dssDictionary = new ModelPdfDict("DSS");

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

	private void addNewToken(final Token crlToken, final ModelPdfArray pdfArray) throws DSSException {
		try {
			final ModelPdfStream stream = new ModelPdfStream(crlToken.getEncoded());
			pdfArray.add(stream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

}
