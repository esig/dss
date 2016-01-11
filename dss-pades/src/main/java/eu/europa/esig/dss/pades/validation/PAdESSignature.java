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

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CRLRef;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertifiedRole;
import eu.europa.esig.dss.validation.CommitmentType;
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

/**
 * Implementation of AdvancedSignature for PAdES
 */
public class PAdESSignature extends CAdESSignature {

	private static final Logger logger = LoggerFactory.getLogger(PAdESSignature.class);

	private final DSSDocument document;
	private final PdfDssDict dssDictionary;

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
		super(pdfSignatureInfo.getCades().getCmsSignedData(), certPool);
		super.setDetachedContents(pdfSignatureInfo.getCades().getDetachedContents());
		this.document = document;
		this.dssDictionary = pdfSignatureInfo.getDssDictionary();
		this.pdfSignatureInfo = pdfSignatureInfo;
	}

	@Override
	public SignatureForm getSignatureForm() {
		return SignatureForm.PAdES;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return super.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		return super.getDigestAlgorithm();
	}

	@Override
	public PAdESCertificateSource getCertificateSource() {
		if (padesCertSources == null) {
			padesCertSources = new PAdESCertificateSource(dssDictionary, super.getCmsSignedData(), super.getSignerInformation() , certPool);
		}
		return padesCertSources;
	}

	@Override
	public OfflineCRLSource getCRLSource() {
		if (offlineCRLSource == null) {
			offlineCRLSource = new PAdESCRLSource(dssDictionary);
		}
		return offlineCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {
		if (offlineOCSPSource == null) {
			offlineOCSPSource = new PAdESOCSPSource(dssDictionary);
		}
		return offlineOCSPSource;
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {
		return super.getCandidatesForSigningCertificate();
	}

	@Override
	public Date getSigningTime() {
		return pdfSignatureInfo.getSigningDate();
	}

	@Override
	public SignaturePolicy getPolicyId() {
		return super.getPolicyId();
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		String location = pdfSignatureInfo.getLocation();
		if (StringUtils.isBlank(location)) {
			return super.getSignatureProductionPlace();
		} else {
			SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
			signatureProductionPlace.setCountryName(location);
			return signatureProductionPlace;
		}
	}

	@Override
	public String getContentType() {
		return MimeType.PDF.getMimeTypeString();
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
		return super.getClaimedSignerRoles();
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {
		return null;
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {
		return super.getContentTimestamps();
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {
		return super.getContentTimestampData(timestampToken);
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		result.addAll(super.getSignatureTimestamps());
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {

				final PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
				if (timestampToken.getTimeStampType() == TimestampType.SIGNATURE_TIMESTAMP) {

					timestampToken.setTimestampedReferences(getSignatureTimestampedReferences());
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
		final List<String> timestampedTimestamps = new ArrayList<String>();
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		usedCertificatesDigestAlgorithms.add(DigestAlgorithm.SHA1);
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp()) {

				PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
				// return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
				if (timestampToken.getTimeStampType() == TimestampType.ARCHIVE_TIMESTAMP) {

					final List<TimestampReference> references = getSignatureTimestampedReferences();
					for (final String timestampId : timestampedTimestamps) {

						final TimestampReference signatureReference_ = new TimestampReference(timestampId);
						references.add(signatureReference_);
					}
					final List<CertificateToken> certificates = getCertificates();
					for (final CertificateToken certificate : certificates) {
						references.add(createCertificateTimestampReference(certificate));
					}
					timestampToken.setTimestampedReferences(references);
					archiveTimestampTokenList.add(timestampToken);
				}
				timestampedTimestamps.add(timestampToken.getDSSId().asXmlId());
			}

		}
		return Collections.unmodifiableList(archiveTimestampTokenList);
	}
	
	@Override
	public List<TimestampReference> getSignatureTimestampedReferences() {
		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		final TimestampReference signatureReference = new TimestampReference(getId());
		references.add(signatureReference);
		final List<TimestampReference> signingCertificateTimestampReferences = super.getSigningCertificateTimestampReferences();
		references.addAll(signingCertificateTimestampReferences);
		return references;
	}
	
	

	private TimestampReference createCertificateTimestampReference(CertificateToken certificate) {
		final byte[] certificateDigest = DSSUtils.digest(DigestAlgorithm.SHA1, certificate.getEncoded());
		final TimestampReference reference = new TimestampReference(DigestAlgorithm.SHA1.name(), Base64.encodeBase64String(certificateDigest));
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
		signatureCryptographicVerification = super.checkSignatureIntegrity();
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
		return super.getCertificateRefs();
	}

	@Override
	public List<CRLRef> getCRLRefs() {
		return super.getCRLRefs();
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		return super.getOCSPRefs();
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		if (super.getSignatureTimestamps().contains(timestampToken)) {
			return super.getSignatureTimestampData(timestampToken, null);
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

		return pdfSignatureInfo.getCades();
	}

	@Override
	public byte[] getArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
			if (signatureInfo instanceof PdfDocTimestampInfo) {
				PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
				if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
					final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
					return signedDocumentBytes;
				}
			}
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public String getId() {
		String cadesId = super.getId();
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
		switch (signatureLevel) {
			case PAdES_BASELINE_LTA:
				dataForLevelPresent = CollectionUtils.isNotEmpty(getArchiveTimestamps());
				// c &= fct() will process fct() all time ; c = c && fct() will process fct() only if c is true
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_LT);
				break;
			case PAdES_BASELINE_LT:
				dataForLevelPresent = hasDSSDictionary();
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T);
				break;
			case PAdES_BASELINE_T:
				dataForLevelPresent = CollectionUtils.isNotEmpty(getSignatureTimestamps());
				dataForLevelPresent = dataForLevelPresent && isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_B);
				break;
			case PAdES_BASELINE_B:
				dataForLevelPresent = (pdfSignatureInfo != null);
				break;
			default:
				throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		logger.debug("Level {} found on document {} = {}", new Object[] {
				signatureLevel, document.getName(), dataForLevelPresent
		});
		return dataForLevelPresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] {
				SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA
		};
	}

	private boolean hasDSSDictionary() {
		return pdfSignatureInfo.getDssDictionary() != null;
	}

	@Override
	public CommitmentType getCommitmentTypeIndication() {
		return super.getCommitmentTypeIndication();
	}

	public boolean hasOuterSignatures() {
		return CollectionUtils.isNotEmpty(pdfSignatureInfo.getOuterSignatures());
	}

	public PdfSignatureInfo getPdfSignatureInfo() {
		return pdfSignatureInfo;
	}
}