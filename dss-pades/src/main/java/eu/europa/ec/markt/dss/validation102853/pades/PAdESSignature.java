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
package eu.europa.ec.markt.dss.validation102853.pades;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.pdf.PdfDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.pdfbox.PdfDssDict;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.signature.validation.TimestampToken;
import eu.europa.ec.markt.dss.signature.validation.cades.CAdESCertificateSource;
import eu.europa.ec.markt.dss.signature.validation.pades.PAdESCertificateSource;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.TimestampReference;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.bean.CandidatesForSigningCertificate;
import eu.europa.ec.markt.dss.validation102853.bean.CertifiedRole;
import eu.europa.ec.markt.dss.validation102853.bean.CommitmentType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateRef;
import eu.europa.ec.markt.dss.validation102853.crl.CRLRef;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPRef;
import eu.europa.ec.markt.dss.validation102853.ocsp.OfflineOCSPSource;

/**
 * Implementation of AdvancedSignature for PAdES
 *
 */
public class PAdESSignature extends DefaultAdvancedSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESSignature.class);

	private final DSSDocument document;
	private final PdfDssDict pdfCatalog;

	private final PdfDssDict outerCatalog;

	private final CAdESSignature cadesSignature;
	private final List<TimestampToken> cadesTimestamps;
	private final List<TimestampToken> cadesArchiveTimestamps;

	private final PdfSignatureInfo pdfSignatureInfo;

	private PAdESCertificateSource padesCertSources;

	/**
	 * This list represents all digest algorithms used to calculate the digest values of certificates.
	 */
	private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

	/**
	 * The default constructor for PAdESSignature.
	 *
	 * @param document
	 * @param pdfSignatureInfo
	 * @param certPool
	 * @throws DSSException
	 */
	protected PAdESSignature(final DSSDocument document, final PdfSignatureInfo pdfSignatureInfo, final CertificatePool certPool) throws DSSException {

		super(certPool);
		this.document = document;
		this.pdfCatalog = pdfSignatureInfo.getDocumentDictionary();
		this.outerCatalog = pdfSignatureInfo.getOuterCatalog();
		this.cadesSignature = pdfSignatureInfo.getCades();
		this.cadesTimestamps = cadesSignature.getSignatureTimestamps();
		this.cadesArchiveTimestamps = cadesSignature.getArchiveTimestamps();
		this.pdfSignatureInfo = pdfSignatureInfo;
		cadesSignature.setPadesSigningTime(getSigningTime());
	}

	@Override
	public SignatureForm getSignatureForm() {

		return SignatureForm.PAdES;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		return cadesSignature.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {

		return cadesSignature.getDigestAlgorithm();
	}

	@Override
	public PAdESCertificateSource getCertificateSource() {

		if (padesCertSources == null) {

			final CAdESCertificateSource cadesCertSource = cadesSignature.getCertificateSource();
			padesCertSources = new PAdESCertificateSource(getDSSDictionary(), cadesCertSource, certPool);
		}
		return padesCertSources;
	}

	private PdfDssDict getDSSDictionary() {

		PdfDssDict catalog = outerCatalog != null ? outerCatalog : pdfCatalog;
		return catalog;
	}

	@Override
	public OfflineCRLSource getCRLSource() {

		if (offlineCRLSource == null) {

			final PdfDssDict dssDictionary = getDSSDictionary();
			offlineCRLSource = new PAdESCRLSource(cadesSignature, dssDictionary);
		}
		return offlineCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {

		if (offlineOCSPSource == null) {

			final PdfDssDict dssDictionary = getDSSDictionary();
			offlineOCSPSource = new PAdESOCSPSource(cadesSignature, dssDictionary);
		}
		return offlineOCSPSource;
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {

		return cadesSignature.getCandidatesForSigningCertificate();
	}

	@Override
	public Date getSigningTime() {

		if (pdfSignatureInfo.getSigningDate() != null) {
			return pdfSignatureInfo.getSigningDate();
		}
		return null;
	}

	@Override
	public SignaturePolicy getPolicyId() {

		return cadesSignature.getPolicyId();
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		String location = pdfSignatureInfo.getLocation();
		if ((location == null) || (location.trim().length() == 0)) {

			return cadesSignature.getSignatureProductionPlace();
		} else {
			SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
			signatureProductionPlace.setCountryName(location);
			return signatureProductionPlace;
		}
	}

	@Override
	public String getContentType() {

		return "application/pdf";
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
	public String[] getClaimedSignerRoles() {

		return cadesSignature.getClaimedSignerRoles();
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {
		return null;
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {

		final List<TimestampToken> contentTimestamps = cadesSignature.getContentTimestamps();
		return contentTimestamps;
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {

		final byte[] contentTimestampData = cadesSignature.getContentTimestampData(timestampToken);
		return contentTimestampData;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		result.addAll(cadesTimestamps);
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {

				final PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
				if (timestampToken.getTimeStampType() == TimestampType.SIGNATURE_TIMESTAMP) {

					timestampToken.setTimestampedReferences(cadesSignature.getSignatureTimestampedReferences());
					result.add(timestampToken);
				}
			}
		}
		return Collections.unmodifiableList(result);
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {

		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {

		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {

		final List<TimestampToken> archiveTimestampTokenList = new ArrayList<TimestampToken>();
		archiveTimestampTokenList.addAll(cadesArchiveTimestamps); // (Bob) ???
		final List<String> timestampedTimestamps = new ArrayList<String>();
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		usedCertificatesDigestAlgorithms.add(DigestAlgorithm.SHA1);
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (!outerSignature.isTimestamp()) {
				continue;
			}
			PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
			// return this timestamp if it's an archive timestamp
			final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
			if (timestampToken.getTimeStampType() == TimestampType.ARCHIVE_TIMESTAMP) {

				final List<TimestampReference> references = cadesSignature.getSignatureTimestampedReferences();
				for (final String timestampId : timestampedTimestamps) {

					final TimestampReference signatureReference_ = new TimestampReference(timestampId);
					references.add(signatureReference_);
				}
				final List<CertificateToken> certificates = getCertificates();
				for (final CertificateToken certificate : certificates) {

					final byte[] encodedCertificate = certificate.getEncoded();
					final byte[] certificateDigest = DSSUtils.digest(DigestAlgorithm.SHA1, encodedCertificate);
					final TimestampReference certificateTimestampReference = createCertificateTimestampReference(DigestAlgorithm.SHA1,
							certificateDigest);
					references.add(certificateTimestampReference);
				}
				timestampToken.setTimestampedReferences(references);
				archiveTimestampTokenList.add(timestampToken);
			}
			timestampedTimestamps.add(String.valueOf(timestampToken.getDSSId()));
		}
		return Collections.unmodifiableList(archiveTimestampTokenList);
	}

	private TimestampReference createCertificateTimestampReference(final DigestAlgorithm digestAlgorithm, final byte[] certHash) {
		final TimestampReference reference = new TimestampReference(digestAlgorithm.name(), Base64.encodeBase64String(certHash));
		return reference;
	}

	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
	}

	@Override
	public SignatureCryptographicVerification checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return signatureCryptographicVerification;
		}
		signatureCryptographicVerification = pdfSignatureInfo.checkIntegrity();
		return signatureCryptographicVerification;
	}

	@Override
	public void checkSigningCertificate() {

		// TODO-Bob (13/07/2014):
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {

		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		return cadesSignature.getCertificateRefs();
	}

	@Override
	public List<CRLRef> getCRLRefs() {
		return getCAdESSignature().getCRLRefs();
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		return cadesSignature.getOCSPRefs();
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		if (cadesTimestamps.contains(timestampToken)) {
			return cadesSignature.getSignatureTimestampData(timestampToken, null);
		} else {
			for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
				if (signatureInfo instanceof PdfDocTimestampInfo) {
					PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
					if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
						final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
						return signedDocumentBytes;
					}
				}
			}
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		/* Not applicable for PAdES */
		return null;
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {

		/* Not applicable for PAdES */
		return null;
	}

	/**
	 * @return the CAdES signature underlying this PAdES signature
	 */
	public CAdESSignature getCAdESSignature() {

		return cadesSignature;
	}

	@Override
	public byte[] getArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		if (cadesArchiveTimestamps.contains(timestampToken)) {
			return cadesSignature.getArchiveTimestampData(timestampToken, null);
		} else {
			for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
				if (signatureInfo instanceof PdfDocTimestampInfo) {
					PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
					if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
						final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
						return signedDocumentBytes;
					}
				}
			}
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public String getId() {
		String cadesId = cadesSignature.getId();
		return cadesId + getDigestOfByteRange();
	}

	private String getDigestOfByteRange() {
		int[] signatureByteRange = pdfSignatureInfo.getSignatureByteRange();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i : signatureByteRange) {
			baos.write(i);
		}
		return DSSUtils.getMD5Digest(baos);
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

		return usedCertificatesDigestAlgorithms;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(SignatureLevel signatureLevel) {
		boolean dataForLevelPresent = true;
		final List<TimestampToken> signatureTimestamps = getSignatureTimestamps();
		switch (signatureLevel) {
			case PAdES_BASELINE_LTA:
			case PAdES_102778_LTV:
				dataForLevelPresent = hasDocumentTimestampOnTopOfDSSDict();
				// c &= fct() will process fct() all time ; c = c && fct() will process fct() only if c is true
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_LT);
				break;
			case PAdES_BASELINE_LT:
				dataForLevelPresent = hasDSSDictionary();
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T);
				break;
			case PAdES_BASELINE_T:
				dataForLevelPresent = CollectionUtils.isNotEmpty(signatureTimestamps);
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_B);
				break;
			case PAdES_BASELINE_B:
				dataForLevelPresent = (pdfSignatureInfo != null);
				break;
			default:
				throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		LOG.debug("Level {} found on document {} = {}", new Object[] { signatureLevel, document.getName(), dataForLevelPresent });
		return dataForLevelPresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] { SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_LT,
				SignatureLevel.PAdES_102778_LTV, SignatureLevel.PAdES_BASELINE_LTA };
	}

	private boolean hasDSSDictionary() {
		for (final PdfSignatureOrDocTimestampInfo outerSignature : pdfSignatureInfo.getOuterSignatures()) {
			if (outerSignature.getDocumentDictionary() != null) {
				return true;
			}
		}
		return false;
	}

	private boolean hasDocumentTimestampOnTopOfDSSDict() {
		for (final PdfSignatureOrDocTimestampInfo outerSignature : pdfSignatureInfo.getOuterSignatures()) {
			if (outerSignature.getDocumentDictionary() != null) {
				if (outerSignature.isTimestamp()) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		return cadesSignature.getCommitmentTypeIndication();
	}

	public boolean hasOuterSignatures() {
		return !pdfSignatureInfo.getOuterSignatures().isEmpty();
	}

	public PdfSignatureInfo getPdfSignatureInfo() {
		return pdfSignatureInfo;
	}
}
