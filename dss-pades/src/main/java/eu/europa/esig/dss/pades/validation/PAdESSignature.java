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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.dss.PdfVriDictSource;
import eu.europa.esig.dss.pades.validation.scope.PAdESSignatureScopeFinder;
import eu.europa.esig.dss.pades.validation.timestamp.PAdESTimestampSource;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureDigestReference;
import eu.europa.esig.dss.validation.SignatureIdentifierBuilder;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Implementation of AdvancedSignature for PAdES
 */
public class PAdESSignature extends CAdESSignature {

	private static final long serialVersionUID = 3818555396958720967L;

	/** Represents the corresponding PDF revision */
	private final PdfSignatureRevision pdfSignatureRevision;

	/** Contains a complete list of validating document revisions */
	private final List<PdfRevision> documentRevisions;

	/** Represents a certificate source obtained from DSS/VRI revisions */
	private ListCertificateSource dssCertificateSource;

	/** Represents a CRL source obtained from DSS/VRI revisions */
	private ListRevocationSource<CRL> dssCRLSource;

	/** Represents an OCSP source obtained from DSS/VRI revisions */
	private ListRevocationSource<OCSP> dssOCSPSource;

	/** SHA-1 key computed on /Contents of the signature */
	private String vriKey;

	/**
	 * The default constructor for PAdESSignature.
	 *
	 * @param pdfSignatureRevision a related {@link PdfSignatureRevision}
	 * @param documentRevisions    a list of {@link PdfRevision} extracted from the
	 *                             validating document
	 * 
	 */
	protected PAdESSignature(final PdfSignatureRevision pdfSignatureRevision, final List<PdfRevision> documentRevisions) {
		super(pdfSignatureRevision.getCMSSignedData(), DSSASN1Utils.getFirstSignerInformation(pdfSignatureRevision.getCMSSignedData()));
		this.pdfSignatureRevision = pdfSignatureRevision;
		this.documentRevisions = documentRevisions;
		this.detachedContents = Arrays.asList(pdfSignatureRevision.getSignedData());
	}

	/**
	 * Sets a joint DSS/VRI Certificate Source
	 *
	 * @param dssCertificateSource {@link ListCertificateSource}
	 */
	public void setDssCertificateSource(ListCertificateSource dssCertificateSource) {
		this.dssCertificateSource = dssCertificateSource;
	}

	/**
	 * Sets a joint DSS/VRI CRL Source
	 *
	 * @param dssCRLSource {@link ListRevocationSource}
	 */
	public void setDssCRLSource(ListRevocationSource<CRL> dssCRLSource) {
		this.dssCRLSource = dssCRLSource;
	}

	/**
	 * Sets a joint DSS/VRI OCSP Source
	 *
	 * @param dssOCSPSource {@link ListRevocationSource}
	 */
	public void setDssOCSPSource(ListRevocationSource<OCSP> dssOCSPSource) {
		this.dssOCSPSource = dssOCSPSource;
	}

	@Override
	public SignatureForm getSignatureForm() {
		if (hasPKCS7SubFilter()) {
			return SignatureForm.PKCS7;
		}
		return SignatureForm.PAdES;
	}

	@Override
	public SignatureCertificateSource getCertificateSource() {
		if (offlineCertificateSource == null) {
			offlineCertificateSource = new PAdESCertificateSource(pdfSignatureRevision, getVRIKey(), getSignerInformation());
		}
		return offlineCertificateSource;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (signatureCRLSource == null) {
			signatureCRLSource = new PAdESCRLSource(pdfSignatureRevision, getVRIKey(), getSignerInformation().getSignedAttributes());
		}
		return signatureCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (signatureOCSPSource == null) {
			signatureOCSPSource = new PAdESOCSPSource(pdfSignatureRevision, getVRIKey(), getSignerInformation().getSignedAttributes());
		}
		return signatureOCSPSource;
	}

	@Override
	public ListCertificateSource getCompleteCertificateSource() {
		ListCertificateSource completeCertificateSource = super.getCompleteCertificateSource();
		if (dssCertificateSource != null) {
			completeCertificateSource.addAll(dssCertificateSource);
		}
		return completeCertificateSource;
	}

	@Override
	public ListRevocationSource<CRL> getCompleteCRLSource() {
		ListRevocationSource<CRL> completeCRLSource = super.getCompleteCRLSource();
		if (dssCRLSource != null) {
			completeCRLSource.addAll(dssCRLSource);
		}
		return completeCRLSource;
	}

	@Override
	public ListRevocationSource<OCSP> getCompleteOCSPSource() {
		ListRevocationSource<OCSP> completeOCSPSource = super.getCompleteOCSPSource();
		if (dssOCSPSource != null) {
			completeOCSPSource.addAll(dssOCSPSource);
		}
		return completeOCSPSource;
	}

	@Override
	public PAdESTimestampSource getTimestampSource() {
		if (signatureTimestampSource == null) {
			signatureTimestampSource = new PAdESTimestampSource(this, documentRevisions);
		}
		return (PAdESTimestampSource) signatureTimestampSource;
	}

	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		return getTimestampSource().getDocumentTimestamps();
	}

	/**
	 * Returns a list of timestamps enveloped within /VRI dictionary for the current signature
	 *
	 * @return a list of {@code TimestampToken}s
	 */
	public List<TimestampToken> getVRITimestamps() {
		return getTimestampSource().getVriTimestamps();
	}

	@Override
	protected List<SignatureScope> findSignatureScopes() {
		return new PAdESSignatureScopeFinder().findSignatureScope(this);
	}

	@Override
	public Date getSigningTime() {
		return pdfSignatureRevision.getSigningDate();
	}

	@Override
	public String getContentIdentifier() {
		return null;
	}

	@Override
	public String getContentHints() {
		return null;
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public DSSDocument getOriginalDocument() {
		return pdfSignatureRevision.getSignedData();
	}

	@Override
	protected DSSDocument getSignerDocumentContent() {
		DSSDocument signerDocument = getOriginalDocument();
		/*
		 * ISO 32000-1:
		 *
		 * adbe.pkcs7.sha1: The SHA-1 digest of the document’s byte range shall be encapsulated in
		 * the CMSSignedData field with ContentInfo of type Data.
		 */
		if (signerDocument != null && getPdfSignatureDictionary() != null &&
				PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(getPdfSignatureDictionary().getSubFilter())) {
			signerDocument = new InMemoryDocument(signerDocument.getDigestValue(DigestAlgorithm.SHA1));
		}
		return signerDocument;
	}

	@Override
	protected SignatureIdentifierBuilder getSignatureIdentifierBuilder() {
		return new PAdESSignatureIdentifierBuilder(this);
	}

	/**
	 * TS 119 442 - V1.1.1 - Electronic Signatures and Infrastructures (ESI), ch. 5.1.4.2.1.3 XML component:
	 * 
	 * In case of PAdES signatures, the input of the digest value computation shall be the result of decoding the
	 * hexadecimal string present within the Contents field of the Signature PDF dictionary enclosing one PAdES
	 * digital signature. 
	 */
	@Override
	public SignatureDigestReference getSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
		byte[] contents = getPdfSignatureDictionary().getContents();
		byte[] digestValue = DSSUtils.digest(digestAlgorithm, contents);
		return new SignatureDigestReference(new Digest(digestAlgorithm, digestValue));
	}

	@Override
	public SignatureLevel getDataFoundUpToLevel() {
		SignatureForm signatureForm = getSignatureForm();
		if (SignatureForm.PAdES.equals(signatureForm) && hasBProfile()) {
			if (!hasTProfile()) {
				return SignatureLevel.PAdES_BASELINE_B;
			}
			if (!hasLTProfile()) {
				return SignatureLevel.PAdES_BASELINE_T;
			}
			if (hasLTAProfile()) {
				return SignatureLevel.PAdES_BASELINE_LTA;
			}
			return SignatureLevel.PAdES_BASELINE_LT;

		} else if (SignatureForm.PKCS7.equals(signatureForm) && hasPKCS7Profile()) {
			if (!hasPKCS7TProfile()) {
				return SignatureLevel.PKCS7_B;
			}
			if (!hasPKCS7LTProfile()) {
				return SignatureLevel.PKCS7_T;
			}
			if (hasPKCS7LTAProfile()) {
				return SignatureLevel.PKCS7_LTA;
			}
			return SignatureLevel.PKCS7_LT;

		} else {
			return SignatureLevel.PDF_NOT_ETSI;
		}
	}

	@Override
	protected PAdESBaselineRequirementsChecker getBaselineRequirementsChecker() {
		return (PAdESBaselineRequirementsChecker) super.getBaselineRequirementsChecker();
	}

	@Override
	protected PAdESBaselineRequirementsChecker createBaselineRequirementsChecker() {
		return new PAdESBaselineRequirementsChecker(this, offlineCertificateVerifier);
	}

	/**
	 * Checks the presence of PKCS#7 corresponding SubFilter
	 *
	 * @return true if PKCS#7 Profile is detected
	 */
	public boolean hasPKCS7Profile() {
		return getBaselineRequirementsChecker().hasPKCS7Profile();
	}

	/**
	 * Checks the presence of a signature-time-stamp
	 *
	 * @return true if PKCS#7-T Profile is detected
	 */
	public boolean hasPKCS7TProfile() {
		return getBaselineRequirementsChecker().hasPKCS7TProfile();
	}

	/**
	 * Checks the presence of a validation data
	 *
	 * @return true if PKCS#7-LT Profile is detected
	 */
	public boolean hasPKCS7LTProfile() {
		return getBaselineRequirementsChecker().hasPKCS7LTProfile();
	}

	/**
	 * Checks the presence of an archive-time-stamp
	 *
	 * @return true if PKCS#7-LTA Profile is detected
	 */
	public boolean hasPKCS7LTAProfile() {
		return getBaselineRequirementsChecker().hasPKCS7LTAProfile();
	}

	/**
	 * Checks the presence of ArchiveTimeStamp element in the signature, what is the proof -A profile existence
	 *
	 * @return true if the -A extension is present
	 */
	@Override
	public boolean hasAProfile() {
		return getBaselineRequirementsChecker().hasExtendedAProfile();
	}

	/**
	 * Gets the last DSS dictionary for the signature
	 *
	 * @return {@link PdfDssDict}
	 */
	public PdfDssDict getDssDictionary() {
		return pdfSignatureRevision.getDssDictionary();
	}

	private boolean hasPKCS7SubFilter() {
		if (pdfSignatureRevision != null) {
			String subFilter = pdfSignatureRevision.getPdfSigDictInfo().getSubFilter();
			return PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(subFilter) ||
					PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(subFilter);
		}
		return false;
	}

	/**
	 * Retrieves a PdfRevision (PAdES) related to the current signature
	 * 
	 * @return {@link PdfRevision}
	 */
	public PdfSignatureRevision getPdfRevision() {
		return pdfSignatureRevision;
	}

	/**
	 * Gets the {@code PdfSignatureDictionary}
	 *
	 * @return {@link PdfSignatureDictionary}
	 */
	public PdfSignatureDictionary getPdfSignatureDictionary() {
		return pdfSignatureRevision.getPdfSigDictInfo();
	}

	/**
	 * Name of the related to the signature VRI dictionary
	 *
	 * @return related {@link String} VRI dictionary name
	 */
	public String getVRIKey() {
		if (vriKey == null) {
			// By ETSI EN 319 142-1 V1.1.1, VRI dictionary's name is the base-16-encoded (uppercase)
			// SHA1 digest of the signature to which it applies
			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, getPdfSignatureDictionary().getContents());
			String vriId = Utils.toHex(digest);
			vriKey = vriId.toUpperCase();
		}
		return vriKey;
	}

	/**
	 * Returns a VRI creation time defined within 'TU' field of a corresponding /VRI dictionary
	 *
	 * @return {@link Date} of VRI dictionary creation, when present
	 */
	public Date getVRICreationTime() {
		PdfDssDict dssDictionary = getDssDictionary();
		if (dssDictionary != null) {
			PdfVriDictSource pdfVriDictTimestampSource = new PdfVriDictSource(dssDictionary, getVRIKey());
			return pdfVriDictTimestampSource.getVRICreationTime();
		}
		return null;
	}

	@Override
	public void addExternalTimestamp(TimestampToken timestamp) {
		throw new UnsupportedOperationException("The action is not supported for PAdES!");
	}

}
