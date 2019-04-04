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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertifiedRole;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

/**
 * Implementation of AdvancedSignature for PAdES
 */
public class PAdESSignature extends CAdESSignature {

	private static final long serialVersionUID = 3818555396958720967L;

	private static final Logger LOG = LoggerFactory.getLogger(PAdESSignature.class);

	private final DSSDocument document;
	private final PdfDssDict dssDictionary;

	private final PdfSignatureInfo pdfSignatureInfo;

	private PAdESCertificateSource padesCertSources;

	/**
	 * The default constructor for PAdESSignature.
	 *
	 * @param document
	 * @param pdfSignatureInfo
	 * @param certPool
	 * @throws DSSException
	 */
	protected PAdESSignature(final DSSDocument document, final PdfSignatureInfo pdfSignatureInfo, final CertificatePool certPool) throws DSSException {
		super(pdfSignatureInfo.getCades().getCmsSignedData(), certPool, pdfSignatureInfo.getCades().getDetachedContents());
		this.document = document;
		this.dssDictionary = pdfSignatureInfo.getDssDictionary();
		this.pdfSignatureInfo = pdfSignatureInfo;
	}

	@Override
	public SignatureForm getSignatureForm() {
		if (hasPKCS7SubFilter()) {
			return SignatureForm.PKCS7;
		}
		return SignatureForm.PAdES;
	}

	@Override
	public PAdESCertificateSource getCertificateSource() {
		if (padesCertSources == null) {
			padesCertSources = new PAdESCertificateSource(dssDictionary, super.getCmsSignedData(), certPool);
		}
		return padesCertSources;
	}

	@Override
	public SignatureCRLSource getCRLSource() {
		if (offlineCRLSource == null) {
			offlineCRLSource = new PAdESCRLSource(dssDictionary, getSignatureVRIName());
		}
		return offlineCRLSource;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		if (offlineOCSPSource == null) {
			offlineOCSPSource = new PAdESOCSPSource(dssDictionary, getSignatureVRIName());
		}
		return offlineOCSPSource;
	}

	@Override
	public Date getSigningTime() {
		return pdfSignatureInfo.getSigningDate();
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {
		String location = pdfSignatureInfo.getLocation();
		if (Utils.isStringBlank(location)) {
			return super.getSignatureProductionPlace();
		} else {
			SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
			signatureProductionPlace.setCountryName(location);
			return signatureProductionPlace;
		}
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
	public List<CertifiedRole> getCertifiedSignerRoles() {
		return null;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {
		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		// CAdES timestamps
		result.addAll(super.getSignatureTimestamps());

		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {

				final PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
				if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {

					timestampToken.setTimestampedReferences(getSignatureTimestampReferences());
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
		final List<TimestampToken> timestampedTimestamps = new ArrayList<TimestampToken>();
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();

		for (TimestampToken token : getSignatureTimestamps()) {
			timestampedTimestamps.add(token);
		}

		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp()) {

				PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
				if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {

					final List<TimestampReference> references = getSignatureTimestampReferences();

					addReferencesForPreviousTimestamps(references, timestampedTimestamps);
					addReferencesForCertificates(references);
					addReferencesFromRevocationData(references);

					timestampToken.setTimestampedReferences(references);
					archiveTimestampTokenList.add(timestampToken);
				}
				timestampedTimestamps.add(timestampToken);
			}

		}
		return Collections.unmodifiableList(archiveTimestampTokenList);
	}

	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {
			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {
				final PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
				timestampToken.setTimestampedReferences(getSignatureTimestampReferences());
				result.add(timestampToken);
			}
		}
		return Collections.unmodifiableList(result);
	}

	@Override
	protected void addReferencesForCertificates(List<TimestampReference> references) {
		List<CertificateToken> dssDictionaryCertValues = getCertificateSource().getDSSDictionaryCertValues();
		for (CertificateToken certificate : dssDictionaryCertValues) {
			addReference(references, new TimestampReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		List<CertificateToken> vriDictionaryCertValues = getCertificateSource().getVRIDictionaryCertValues();
		for (CertificateToken certificate : vriDictionaryCertValues) {
			addReference(references, new TimestampReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
	}

	/**
	 * This method adds references to retrieved revocation data.
	 * 
	 * @param references
	 */
	@Override
	protected void addReferencesFromRevocationData(List<TimestampReference> references) {
		List<RevocationToken> vriRevocationTokens = getVRIDictionaryRevocationTokens();
		for (RevocationToken revocationToken : vriRevocationTokens) {
			addReference(references, new TimestampReference(revocationToken.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
		}

		List<RevocationToken> dssRevocationTokens = getDSSDictionaryRevocationTokens();
		for (RevocationToken revocationToken : dssRevocationTokens) {
			addReference(references, new TimestampReference(revocationToken.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
		}
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {
		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		List<CertificateRef> refs = new ArrayList<CertificateRef>();
		// other are unsigned and should be added in the DSS Dictionary
		List<CertificateToken> encapsulatedCertificates = getCAdESSignature().getCertificateSource().getKeyInfoCertificates();
		addCertRefs(refs, encapsulatedCertificates);
		if (dssDictionary != null) {
			Map<Long, CertificateToken> certMap = dssDictionary.getCERTs();
			addCertRefs(refs, certMap.values());
		}
		return refs;
	}

	private void addCertRefs(List<CertificateRef> refs, Collection<CertificateToken> encapsulatedCertificates) {
		for (CertificateToken certificateToken : encapsulatedCertificates) {
			CertificateRef ref = new CertificateRef();
			ref.setCertDigest(new Digest(DigestAlgorithm.SHA1, certificateToken.getDigest(DigestAlgorithm.SHA1)));
			refs.add(ref);
		}
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
		return DSSUtils.getMD5Digest(baos.toByteArray());
	}

	@Override
	public int[] getSignatureByteRange() {
		return pdfSignatureInfo.getSignatureByteRange();
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {
		/* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public boolean isDataForSignatureLevelPresent(SignatureLevel signatureLevel) {
		boolean dataForLevelPresent = true;
		switch (signatureLevel) {
		case PDF_NOT_ETSI:
			break;
		case PAdES_BASELINE_LTA:
			dataForLevelPresent = hasLTAProfile() && hasLTProfile() && hasCAdESDetachedSubFilter();
			break;
		case PKCS7_LTA:
			dataForLevelPresent = hasLTAProfile() && hasLTProfile() && hasPKCS7SubFilter();
			break;
		case PAdES_BASELINE_LT:
			dataForLevelPresent = hasLTProfile() && (hasTProfile() || hasLTAProfile()) && hasCAdESDetachedSubFilter();
			break;
		case PKCS7_LT:
			dataForLevelPresent = hasLTProfile() && (hasTProfile() || hasLTAProfile()) && hasPKCS7SubFilter();
			break;
		case PAdES_BASELINE_T:
			dataForLevelPresent = hasTProfile() && hasCAdESDetachedSubFilter();
			break;
		case PKCS7_T:
			dataForLevelPresent = hasTProfile() && hasPKCS7SubFilter();
			break;
		case PAdES_BASELINE_B:
			dataForLevelPresent = hasCAdESDetachedSubFilter();
			break;
		case PKCS7_B:
			dataForLevelPresent = hasPKCS7SubFilter();
			break;
		default:
			throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		LOG.debug("Level {} found on document {} = {}", signatureLevel, document.getName(), dataForLevelPresent);
		return dataForLevelPresent;
	}

	private boolean hasCAdESDetachedSubFilter() {
		return (pdfSignatureInfo != null) && "ETSI.CAdES.detached".equals(pdfSignatureInfo.getSubFilter());
	}

	private boolean hasPKCS7SubFilter() {
		return (pdfSignatureInfo != null) && "adbe.pkcs7.detached".equals(pdfSignatureInfo.getSubFilter());
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[] { SignatureLevel.PDF_NOT_ETSI, SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PKCS7_B, SignatureLevel.PAdES_BASELINE_T,
				SignatureLevel.PKCS7_T, SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PKCS7_LT, SignatureLevel.PAdES_BASELINE_LTA,
				SignatureLevel.PKCS7_LTA };
	}

	public boolean hasOuterSignatures() {
		return Utils.isCollectionNotEmpty(pdfSignatureInfo.getOuterSignatures());
	}

	public PdfSignatureInfo getPdfSignatureInfo() {
		return pdfSignatureInfo;
	}
	
	@Override
	public String getSignatureFieldName() {
		return pdfSignatureInfo.getSigFieldName();
	}

	@Override
	public String getSignerName() {
		return pdfSignatureInfo.getSignerName();
	}

	@Override
	public String getFilter() {
		return pdfSignatureInfo.getFilter();
	}

	@Override
	public String getSubFilter() {
		return pdfSignatureInfo.getSubFilter();
	}

	@Override
	public String getContactInfo() {
		return pdfSignatureInfo.getContactInfo();
	}

	@Override
	public String getReason() {
		return pdfSignatureInfo.getReason();
	}
	
	/**
	 * Name of the related to the signature VRI dictionary
	 * @return related {@link String} VRI dictionary name
	 */
	private String getSignatureVRIName() {
		// By ETSI EN 319 142-1 V1.1.1, VRI dictionary's name is the base-16-encoded (uppercase)
		// SHA1 digest of the signature to which it applies
		return DSSUtils.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, pdfSignatureInfo.getContent())).toUpperCase();
	}

}
