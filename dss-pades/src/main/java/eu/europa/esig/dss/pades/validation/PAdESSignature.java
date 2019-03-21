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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CRLRef;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.CertifiedRole;
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.validation.TimestampReference;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

/**
 * Implementation of AdvancedSignature for PAdES
 */
public class PAdESSignature extends CAdESSignature {

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
			offlineCRLSource = new PAdESCRLSource(dssDictionary);
		}
		return offlineCRLSource;
	}

	@Override
	public SignatureOCSPSource getOCSPSource() {
		if (offlineOCSPSource == null) {
			offlineOCSPSource = new PAdESOCSPSource(dssDictionary);
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
	public List<CertifiedRole> getCertifiedSignerRoles() {
		return null;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		result.addAll(super.getSignatureTimestamps());
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {

				final PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
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

		for (TimestampToken token : super.getSignatureTimestamps()) {
			timestampedTimestamps.add(token.getDSSIdAsString());
		}

		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp()) {

				PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
				if (timestampToken.getTimeStampType() == TimestampType.ARCHIVE_TIMESTAMP) {
					final List<TimestampReference> references = getSignatureTimestampedReferences();
					for (final String timestampId : timestampedTimestamps) {
						references.add(new TimestampReference(timestampId, TimestampedObjectType.TIMESTAMP));
					}
					final List<CertificateRef> certRefs = getCertificateRefs();
					for (final CertificateRef certRef : certRefs) {
						references.add(createCertificateTimestampReference(certRef));
					}

					addReferencesFromOfflineCRLSource(references);
					addReferencesFromOfflineOCSPSource(references);

					timestampToken.setTimestampedReferences(references);
					archiveTimestampTokenList.add(timestampToken);
				}
				timestampedTimestamps.add(timestampToken.getDSSIdAsString());
			}

		}
		return Collections.unmodifiableList(archiveTimestampTokenList);
	}

	@Override
	public List<TimestampReference> getSignatureTimestampedReferences() {
		final List<TimestampReference> references = new ArrayList<TimestampReference>();
		// timestamp of the current signature
		references.add(new TimestampReference(getId()));
		// retrieve references from CMS Object
		final List<TimestampReference> signingCertificateTimestampReferences = super.getSigningCertificateTimestampReferences();
		for (TimestampReference timestampReference : signingCertificateTimestampReferences) {
			usedCertificatesDigestAlgorithms.add(timestampReference.getDigestAlgorithm());
		}
		references.addAll(signingCertificateTimestampReferences);
		return references;
	}

	private TimestampReference createCertificateTimestampReference(CertificateRef ref) {
		usedCertificatesDigestAlgorithms.add(ref.getDigestAlgorithm());
		return new TimestampReference(ref.getDigestAlgorithm(), ref.getDigestValue(), TimestampedObjectType.CERTIFICATE);
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
			Map<Long, CertificateToken> certMap = dssDictionary.getCertMap();
			addCertRefs(refs, certMap.values());
		}
		return refs;
	}

	private void addCertRefs(List<CertificateRef> refs, Collection<CertificateToken> encapsulatedCertificates) {
		for (CertificateToken certificateToken : encapsulatedCertificates) {
			CertificateRef ref = new CertificateRef();
			ref.setDigestAlgorithm(DigestAlgorithm.SHA1);
			ref.setDigestValue(certificateToken.getDigest(DigestAlgorithm.SHA1));
			refs.add(ref);
		}
	}

	@Override
	public List<CRLRef> getCRLRefs() {
		return Collections.emptyList();
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		return Collections.emptyList();
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
	public String getSignatureName() {
		return pdfSignatureInfo.getSignatureName();
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

}
