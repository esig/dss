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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections.CollectionUtils;

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
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.PdfStream;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * PAdES Baseline LT signature
 */
class PAdESLevelBaselineLT implements SignatureExtension<PAdESSignatureParameters> {

	// the information read from the signatures
	final PdfObjFactory factory = PdfObjFactory.getInstance();
	private PdfArray dssCertArray = factory.newArray();
	private PdfArray dssOcspArray = factory.newArray();
	private PdfArray dssCrlArray = factory.newArray();

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
			PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
			pdfDocumentValidator.setCertificateVerifier(certificateVerifier);

			List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
			for (final AdvancedSignature signature : signatures) {
				if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T)) {
					final PAdESLevelBaselineT padesLevelBaselineT = new PAdESLevelBaselineT(tspSource);
					document = padesLevelBaselineT.extendSignatures(document, parameters);
					break;
				}
			}

			// create DSS dictionary
			PdfDict dssDictionary = factory.newDict("DSS");
			for (final AdvancedSignature signature : signatures) {
				if (signature instanceof PAdESSignature) {
					PAdESSignature pAdESSignature = (PAdESSignature) signature;
					SignatureValidationCallBack callback = new SignatureValidationCallBack();
					validate(pAdESSignature, callback);
					includeToDssDictionary(dssDictionary, callback);
				}
			}

			addGlobalCertsCrlsOcsps(dssDictionary);

			final ByteArrayOutputStream baos = new ByteArrayOutputStream();

			Map<String, PdfDict> dictionariesToAdd = new HashMap<String, PdfDict>();
			dictionariesToAdd.put("DSS", dssDictionary);

			final PDFSignatureService signatureService = factory.newPAdESSignatureService();
			signatureService.addDictionaries(document.openStream(), baos, dictionariesToAdd);

			final InMemoryDocument inMemoryDocument = new InMemoryDocument(baos.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void includeToDssDictionary(PdfDict dssDictionary, SignatureValidationCallBack callback) throws IOException {

		PdfDict vriDictionary = ensureNotNull(dssDictionary, "VRI");

		PdfDict sigVriDictionary = factory.newDirectDict();

		PAdESSignature signature = callback.getSignature();
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, signature.getCAdESSignature().getCmsSignedData().getEncoded());
		String hexHash = Hex.encodeHexString(digest).toUpperCase();

		if (CollectionUtils.isNotEmpty(callback.getCertificates())) {
			PdfArray vriCertArray = factory.newArray();
			for (CertificateToken token : callback.getCertificates()) {
				PdfStream stream = factory.newStream(token.getEncoded());
				vriCertArray.add(stream);
				dssCertArray.add(stream);
			}
			sigVriDictionary.add("Cert", factory.newStreamArray(vriCertArray));
		}

		if (CollectionUtils.isNotEmpty(callback.getCrls())) {
			PdfArray vriCrlArray = factory.newArray();
			for (CRLToken token : callback.getCrls()) {
				PdfStream stream = factory.newStream(token.getEncoded());
				vriCrlArray.add(stream);
				dssCrlArray.add(stream);
			}
			sigVriDictionary.add("CRL", factory.newStreamArray(vriCrlArray));
		}

		if (CollectionUtils.isNotEmpty(callback.getOcsps())) {
			PdfArray vriOcspArray = factory.newArray();
			for (OCSPToken token : callback.getOcsps()) {
				PdfStream stream = factory.newStream(token.getEncoded());
				vriOcspArray.add(stream);
				dssOcspArray.add(stream);
			}
			sigVriDictionary.add("OCSP", factory.newStreamArray(vriOcspArray));
		}

		vriDictionary.add(hexHash, sigVriDictionary);

	}

	private void addGlobalCertsCrlsOcsps(PdfDict dssDictionary) {
		if (dssCertArray.size() > 0) {
			dssDictionary.add("Certs", dssCertArray);
		}
		if (dssCrlArray.size() > 0) {
			dssDictionary.add("CRLs", dssCrlArray);
		}
		if (dssOcspArray.size() > 0) {
			dssDictionary.add("OCSPs", dssOcspArray);
		}
	}

	private PdfDict ensureNotNull(PdfDict dssDictionary, String dictionaryName) {
		PdfDict dictionary = dssDictionary.getAsDict(dictionaryName);
		if (dictionary == null) {
			dictionary = factory.newDict();
			dssDictionary.add(dictionaryName, dictionary);
		}
		return dictionary;
	}

	private void validate(PAdESSignature signature, SignatureValidationCallBack validationCallback) {

		CAdESSignature cadesSignature = signature.getCAdESSignature();
		ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);
		DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusionInProfileLT = cadesSignature.getRevocationDataForInclusion(validationContext);

		validationCallback.setSignature(signature);
		validationCallback.setCrls(revocationsForInclusionInProfileLT.crlTokens);
		validationCallback.setOcsps(revocationsForInclusionInProfileLT.ocspTokens);

		Set<CertificateToken> certs = new HashSet<CertificateToken>(cadesSignature.getCertificates());
		validationCallback.setCertificates(certs);
	}

	class SignatureValidationCallBack {

		private PAdESSignature signature;
		private List<CRLToken> crls;
		private List<OCSPToken> ocsps;
		private Set<CertificateToken> certificates;

		public PAdESSignature getSignature() {
			return signature;
		}

		public void setSignature(PAdESSignature signature) {
			this.signature = signature;
		}

		public List<CRLToken> getCrls() {
			return crls;
		}

		public void setCrls(List<CRLToken> crls) {
			this.crls = crls;
		}

		public List<OCSPToken> getOcsps() {
			return ocsps;
		}

		public void setOcsps(List<OCSPToken> ocsps) {
			this.ocsps = ocsps;
		}

		public Set<CertificateToken> getCertificates() {
			return certificates;
		}

		public void setCertificates(Set<CertificateToken> certificates) {
			this.certificates = certificates;
		}

	}

}