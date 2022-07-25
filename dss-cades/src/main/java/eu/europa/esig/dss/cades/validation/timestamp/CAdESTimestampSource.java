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
package eu.europa.esig.dss.cades.validation.timestamp;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CAdESSignedAttributes;
import eu.europa.esig.dss.cades.validation.CAdESUnsignedAttributes;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CMSCRLSource;
import eu.europa.esig.dss.validation.CMSCertificateSource;
import eu.europa.esig.dss.validation.CMSOCSPSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.SignatureTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static eu.europa.esig.dss.spi.OID.attributeCertificateRefsOid;
import static eu.europa.esig.dss.spi.OID.attributeRevocationRefsOid;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_sigPolicyStore;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

/**
 * The timestamp source for a CAdES signature
 */
@SuppressWarnings("serial")
public class CAdESTimestampSource extends SignatureTimestampSource<CAdESSignature, CAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampSource.class);

	/**
	 * The default constructor
	 *
	 * @param signature {@link CAdESSignature} to get timestamps for
	 */
	public CAdESTimestampSource(final CAdESSignature signature) {
		super(signature);
	}

	@Override
	protected CAdESTimestampDataBuilder getTimestampDataBuilder() {
		return new CAdESTimestampDataBuilder(signature, certificateSource);
	}

	@Override
	protected SignatureProperties<CAdESAttribute> buildSignedSignatureProperties() {
		return CAdESSignedAttributes.build(signature.getSignerInformation());
	}

	@Override
	protected SignatureProperties<CAdESAttribute> buildUnsignedSignatureProperties() {
		return CAdESUnsignedAttributes.build(signature.getSignerInformation());
	}

	@Override
	protected boolean isContentTimestamp(CAdESAttribute signedAttribute) {
		return id_aa_ets_contentTimestamp.equals(signedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isAllDataObjectsTimestamp(CAdESAttribute signedAttribute) {
		// not applicable for CAdES
		return false;
	}

	@Override
	protected boolean isIndividualDataObjectsTimestamp(CAdESAttribute signedAttribute) {
		// not applicable for CAdES
		return false;
	}

	@Override
	protected boolean isSignatureTimestamp(CAdESAttribute unsignedAttribute) {
		return id_aa_signatureTimeStampToken.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isCompleteCertificateRef(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_certificateRefs.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isAttributeCertificateRef(CAdESAttribute unsignedAttribute) {
		return attributeCertificateRefsOid.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isCompleteRevocationRef(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_revocationRefs.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isAttributeRevocationRef(CAdESAttribute unsignedAttribute) {
		return attributeRevocationRefsOid.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isRefsOnlyTimestamp(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_certCRLTimestamp.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isSigAndRefsTimestamp(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_escTimeStamp.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isCertificateValues(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_certValues.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isRevocationValues(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_revocationValues.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isAttrAuthoritiesCertValues(CAdESAttribute unsignedAttribute) {
		// not applicable for CAdES
		return false;
	}

	@Override
	protected boolean isAttributeRevocationValues(CAdESAttribute unsignedAttribute) {
		// not applicable for CAdES
		return false;
	}

	@Override
	protected boolean isArchiveTimestamp(CAdESAttribute unsignedAttribute) {
		return isArchiveTimestampV2(unsignedAttribute) || isArchiveTimestampV3(unsignedAttribute);
	}
	
	private boolean isArchiveTimestampV2(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_archiveTimestampV2.equals(unsignedAttribute.getASN1Oid());
	}
	
	private boolean isArchiveTimestampV3(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_archiveTimestampV3.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected boolean isTimeStampValidationData(CAdESAttribute unsignedAttribute) {
		// not applicable for CAdES
		return false;
	}

	@Override
	protected boolean isCounterSignature(CAdESAttribute unsignedAttribute) {
		return CMSAttributes.counterSignature.equals(unsignedAttribute.getASN1Oid());
	}
	
	@Override
	protected boolean isSignaturePolicyStore(CAdESAttribute unsignedAttribute) {
		return id_aa_ets_sigPolicyStore.equals(unsignedAttribute.getASN1Oid());
	}

	@Override
	protected TimestampToken makeTimestampToken(CAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		TimeStampToken timestamp = signatureAttribute.toTimeStampToken();
		if (timestamp == null) {
			return null;
		}
		return new TimestampToken(timestamp, timestampType, references);
	}

	@Override
	protected void incorporateArchiveTimestampReferences(TimestampToken timestampToken,
														 List<TimestampToken> previousTimestamps) {
		if (isArchiveTimestampV2(timestampToken)) {
			// for an ATSTv2 all the incorporated unsigned properties are covered
			super.incorporateArchiveTimestampReferences(timestampToken, previousTimestamps);
		}
		// else archive-timestamp-v3
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		addReferences(timestampedReferences, getSignatureTimestampReferences());

		final ASN1Sequence atsHashIndex = DSSASN1Utils.getAtsHashIndex(timestampToken.getUnsignedAttributes());
		if (atsHashIndex != null) {
			final DigestAlgorithm digestAlgorithm = getHashIndexDigestAlgorithm(atsHashIndex);

			final ASN1Sequence certsHashIndex = DSSASN1Utils.getCertificatesHashIndex(atsHashIndex);
			final ASN1Sequence crlHashIndex = DSSASN1Utils.getCRLHashIndex(atsHashIndex);
			addReferences(timestampedReferences, getSignedDataCertificateReferences(certsHashIndex, digestAlgorithm));
			addReferences(timestampedReferences, getSignedDataRevocationReferences(crlHashIndex, digestAlgorithm));

			final ASN1Sequence unsignedAttrsHashIndex = DSSASN1Utils.getUnsignedAttributesHashIndex(atsHashIndex);
			addReferences(timestampedReferences,
					getUnsignedAttributesReferences(unsignedAttrsHashIndex, digestAlgorithm, previousTimestamps));
		}
		timestampToken.getTimestampedReferences().addAll(timestampedReferences);
	}
	
	@Override
	protected List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken) {
		// executed for ArchiveTimestampV2 only
		return getSignatureSignedDataReferences();
	}
	
	private boolean isArchiveTimestampV2(TimestampToken timestampToken) {
		return ArchiveTimestampType.CAdES_V2.equals(timestampToken.getArchiveTimestampType())
				|| ArchiveTimestampType.CAdES.equals(timestampToken.getArchiveTimestampType());
	}

	private List<TimestampedReference> getSignedDataCertificateReferences(final ASN1Sequence certsHashIndex,
			final DigestAlgorithm digestAlgorithm) {
		List<TimestampedReference> references = new ArrayList<>();
		
		SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
		if (signatureCertificateSource instanceof CMSCertificateSource) {
			List<DEROctetString> certsHashList = DSSASN1Utils.getDEROctetStrings(certsHashIndex);
			for (CertificateToken certificate : signatureCertificateSource.getSignedDataCertificates()) {
				if (isDigestValuePresent(certificate.getDigest(digestAlgorithm), certsHashList)) {
					addReference(references, certificate.getDSSId(), TimestampedObjectType.CERTIFICATE);
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("The certificate with id [{}] was not included to the message imprint of timestamp "
										+ "or was added to the CMS SignedData after this ArchiveTimestamp has been incorporated!",
								certificate.getDSSIdAsString());
					}
				}
			}
		}
		return references;
	}
	
	private List<TimestampedReference> getSignedDataRevocationReferences(final ASN1Sequence crlsHashIndex,
			final DigestAlgorithm digestAlgorithm) {
		List<TimestampedReference> references = new ArrayList<>();
		
		// get CRL references
		List<DEROctetString> crlsHashList = DSSASN1Utils.getDEROctetStrings(crlsHashIndex);
		addReferences(references, createReferencesForCRLBinaries(getSignedDataCRLBinaries(crlsHashList, digestAlgorithm)));
		addReferences(references, createReferencesForOCSPBinaries(getSignedDataOCSPResponseBinaries(crlsHashList, digestAlgorithm), certificateSource));
		return references;
	}

	private List<CRLBinary> getSignedDataCRLBinaries(final List<DEROctetString> crlsHashList,
																final DigestAlgorithm digestAlgorithm) {
		List<CRLBinary> crlBinaries = new ArrayList<>();

		OfflineCRLSource signatureCRLSource = signature.getCRLSource();
		if (signatureCRLSource instanceof CMSCRLSource) {
			CMSCRLSource cmsCRLSource = (CMSCRLSource) signatureCRLSource;
			for (EncapsulatedRevocationTokenIdentifier<CRL> crlIdentifier : cmsCRLSource.getCMSSignedDataRevocationBinaries()) {
				CRLBinary crlBinary = (CRLBinary) crlIdentifier;
				if (isDigestValuePresent(crlBinary.getDigestValue(digestAlgorithm), crlsHashList)) {
					crlBinaries.add(crlBinary);
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("The CRL Token with id [{}] was not included to the message imprint of timestamp "
										+ "or was added to the CMS SignedData after this ArchiveTimestamp!",
								crlBinary.asXmlId());
					}
				}
			}
		}

		return crlBinaries;
	}
	
	private List<OCSPResponseBinary> getSignedDataOCSPResponseBinaries(final List<DEROctetString> crlsHashList,
																	   final DigestAlgorithm digestAlgorithm) {
		List<OCSPResponseBinary> ocspBinaries = new ArrayList<>();
		
		OfflineOCSPSource signatureOCSPSource = signature.getOCSPSource();
		if (signatureOCSPSource instanceof CMSOCSPSource) {
			CMSOCSPSource cmsOCSPSource = (CMSOCSPSource) signatureOCSPSource;
			for (EncapsulatedRevocationTokenIdentifier<OCSP> token : cmsOCSPSource.getCMSSignedDataRevocationBinaries()) {
				OCSPResponseBinary binary = (OCSPResponseBinary) token;
				// Compute DERTaggedObject with the same algorithm how it was created
				// See: org.bouncycastle.cms.CMSUtils getOthersFromStore()
				OtherRevocationInfoFormat otherRevocationInfoFormat = new OtherRevocationInfoFormat(binary.getAsn1ObjectIdentifier(),
						DSSASN1Utils.toASN1Primitive(binary.getBasicOCSPRespContent()));
				// false value specifies an implicit encoding method
				DERTaggedObject derTaggedObject = new DERTaggedObject(false, 1, otherRevocationInfoFormat);
				if (isDigestValuePresent(DSSUtils.digest(digestAlgorithm, DSSASN1Utils.getDEREncoded(derTaggedObject)), crlsHashList)) {
					ocspBinaries.add(binary);
				} else {
					LOG.warn("The OCSP Token with id [{}] was not included to the message imprint of timestamp "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							binary.asXmlId());
				}
			}
		}
		return ocspBinaries;
	}
	
	private List<TimestampedReference> getUnsignedAttributesReferences(final ASN1Sequence unsignedAttrsHashIndex,
			final DigestAlgorithm digestAlgorithm, final List<TimestampToken> previousTimestamps) {
		final List<TimestampedReference> references = new ArrayList<>();

		final List<DEROctetString> timestampUnsignedAttributesHashesList = DSSASN1Utils
				.getDEROctetStrings(unsignedAttrsHashIndex);
		
		final SignatureProperties<CAdESAttribute> unsignedSignatureProperties = getUnsignedSignatureProperties();
		for (CAdESAttribute unsignedAttribute : unsignedSignatureProperties.getAttributes()) {
			List<byte[]> octets = DSSASN1Utils.getATSHashIndexV3OctetString(unsignedAttribute.getASN1Oid(),
					unsignedAttribute.getAttrValues());
			for (byte[] bytes : octets) {
				final byte[] digest = DSSUtils.digest(digestAlgorithm, bytes);
				DEROctetString derDigest = new DEROctetString(digest);
				if (timestampUnsignedAttributesHashesList.contains(derDigest)) {
					addReferences(references, getReferencesFromUnsignedProperty(unsignedAttribute, previousTimestamps));
				}
			}
		}

		return references;
	}
	
	private List<TimestampedReference> getReferencesFromUnsignedProperty(CAdESAttribute unsignedAttribute,
			final List<TimestampToken> previousTimestamps) {
		if (unsignedAttribute.isTimeStampToken()) {
			List<TimestampedReference> references = getReferencesFromMatchingTimestamp(unsignedAttribute,
					previousTimestamps);
			if (Utils.isCollectionEmpty(references)) {
				LOG.warn("The timestamp order is broken! Unable to find a covered timestamp.");
			}
			return references;

		} else if (isCompleteCertificateRef(unsignedAttribute) || isAttributeCertificateRef(unsignedAttribute)) {
			return getTimestampedCertificateRefs(unsignedAttribute);

		} else if (isCompleteRevocationRef(unsignedAttribute) || isAttributeRevocationRef(unsignedAttribute)) {
			return getTimestampedRevocationRefs(unsignedAttribute);

		} else if (isCertificateValues(unsignedAttribute)) {
			return getTimestampedCertificateValues(unsignedAttribute);

		} else if (isRevocationValues(unsignedAttribute)) {
			return getTimestampedRevocationValues(unsignedAttribute);

		} else if (isCounterSignature(unsignedAttribute)) {
			List<AdvancedSignature> counterSignatures = getCounterSignatures(unsignedAttribute);
			return getCounterSignaturesReferences(counterSignatures);

		} else {
			LOG.warn("Unable to find an unsigned attribute with the digest from ats-hash-index-v3");

		}

		return Collections.emptyList();
	}

	private List<TimestampedReference> getReferencesFromMatchingTimestamp(CAdESAttribute unsignedAttribute,
			final List<TimestampToken> previousTimestamps) {
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		byte[] derEncoded = DSSASN1Utils.getDEREncoded(asn1Object);
		for (TimestampToken timestampToken : previousTimestamps) {
			if (Arrays.equals(derEncoded, timestampToken.getEncoded())) {
				return getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource);
			}
		}
		return Collections.emptyList();
	}

	@Override
	protected List<TimestampedReference> getSignatureSignedDataReferences() {
		List<TimestampedReference> references = new ArrayList<>();
		
		SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
		if (signatureCertificateSource instanceof CMSCertificateSource) {
			addReferences(references, createReferencesForCertificates(signatureCertificateSource.getSignedDataCertificates()));
		}
		
		OfflineCRLSource signatureCRLSource = signature.getCRLSource();
		if (signatureCRLSource instanceof CMSCRLSource) {
			addReferences(references, createReferencesForCRLBinaries(signatureCRLSource.getCMSSignedDataRevocationBinaries()));
		}
		
		OfflineOCSPSource signatureOCSPSource = signature.getOCSPSource();
		if (signatureOCSPSource instanceof CMSOCSPSource) {
			addReferences(references, createReferencesForOCSPBinaries(signatureOCSPSource.getCMSSignedDataRevocationBinaries(), certificateSource));
		}
		
		return references;
	}
	
	private DigestAlgorithm getHashIndexDigestAlgorithm(ASN1Sequence atsHashIndex) {
		AlgorithmIdentifier algorithmIdentifier = DSSASN1Utils.getAlgorithmIdentifier(atsHashIndex);
		return algorithmIdentifier != null ? 
				DigestAlgorithm.forOID(algorithmIdentifier.getAlgorithm().getId()) : CMSUtils.DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO;
	}
	
	private boolean isDigestValuePresent(final byte[] digestValue, final List<DEROctetString> hashList) {
		return hashList.contains(new DEROctetString(digestValue));
	}

	@Override
	protected List<CertificateRef> getCertificateRefs(CAdESAttribute unsignedAttribute) {
		List<CertificateRef> certRefs = new ArrayList<>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			OtherCertID otherCertId = OtherCertID.getInstance(seq.getObjectAt(ii));
			certRefs.add(DSSASN1Utils.getCertificateRef(otherCertId));
		}
		return certRefs;
	}

	@Override
	protected List<CRLRef> getCRLRefs(CAdESAttribute unsignedAttribute) {
		List<CRLRef> refs = new ArrayList<>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			final CrlOcspRef otherRefId = CrlOcspRef.getInstance(seq.getObjectAt(ii));
			final CrlListID otherCrlIds = otherRefId.getCrlids();
			if (otherCrlIds != null) {
				for (final CrlValidatedID id : otherCrlIds.getCrls()) {
					refs.add(new CRLRef(id));
				}
			}
		}
		return refs;
	}

	@Override
	protected List<OCSPRef> getOCSPRefs(CAdESAttribute unsignedAttribute) {
		List<OCSPRef> refs = new ArrayList<>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int i = 0; i < seq.size(); i++) {
			final CrlOcspRef otherCertId = CrlOcspRef.getInstance(seq.getObjectAt(i));
			final OcspListID ocspListID = otherCertId.getOcspids();
			if (ocspListID != null) {
				for (final OcspResponsesID ocspResponsesID : ocspListID.getOcspResponses()) {
					refs.add(new OCSPRef(ocspResponsesID));
				}
			}
		}
		return refs;
	}

	@Override
	protected List<Identifier> getEncapsulatedCertificateIdentifiers(CAdESAttribute unsignedAttribute) {
		List<Identifier> certificateIdentifiers = new ArrayList<>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			try {
				final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
				CertificateToken certificateToken = DSSUtils.loadCertificate(cs.getEncoded());
				certificateIdentifiers.add(certificateToken.getDSSId());
			} catch (Exception e) {
				String errorMessage = "Unable to parse an encapsulated certificate : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, e.getMessage());
				}
			}
		}
		return certificateIdentifiers;
	}

	@Override
	protected List<CRLBinary> getEncapsulatedCRLIdentifiers(CAdESAttribute unsignedAttribute) {
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			return buildCRLIdentifiers(revocationValues.getCrlVals());
		}
		return Collections.emptyList();
	}

	/**
	 * Builds a list of CRL identifiers for the given {@code revVals}
	 *
	 * @param crlVals instances of {@link CertificateList} representing CRL entries
	 * @return a list of {@link CRLBinary}
	 */
	protected List<CRLBinary> buildCRLIdentifiers(CertificateList... crlVals) {
		List<CRLBinary> crlBinaryIdentifiers = new ArrayList<>();
		if (Utils.isArrayNotEmpty(crlVals)) {
			for (final CertificateList revValue : crlVals) {
				try {
					crlBinaryIdentifiers.add(CRLUtils.buildCRLBinary(revValue.getEncoded()));
				} catch (Exception e) {
					String errorMessage = "Unable to parse CRL binaries : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}
			}
		}
		return crlBinaryIdentifiers;
	}

	@Override
	protected List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(CAdESAttribute unsignedAttribute) {
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			return buildOCSPIdentifiers(DSSASN1Utils.toBasicOCSPResps(revocationValues.getOcspVals()));
		}
		return Collections.emptyList();
	}

	/**
	 * Builds a list of OCSP identifiers for the given {@code ocspVals}
	 *
	 * @param ocspVals instances of {@link BasicOCSPResponse} representing OCSP basic responses
	 * @return a list of {@link OCSPResponseBinary}
	 */
	protected List<OCSPResponseBinary> buildOCSPIdentifiers(BasicOCSPResp... ocspVals) {
		List<OCSPResponseBinary> ocspIdentifiers = new ArrayList<>();
		if (Utils.isArrayNotEmpty(ocspVals)) {
			for (final BasicOCSPResp basicOCSPResp : ocspVals) {
				try {
					ocspIdentifiers.add(OCSPResponseBinary.build(basicOCSPResp));
				} catch (Exception e) {
					String errorMessage = "Unable to parse OCSP response binaries : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}
			}
		}
		return ocspIdentifiers;
	}

	@Override
	protected ArchiveTimestampType getArchiveTimestampType(CAdESAttribute unsignedAttribute) {
		if (id_aa_ets_archiveTimestampV2.equals(unsignedAttribute.getASN1Oid())) {
			return ArchiveTimestampType.CAdES_V2;
		} else if (id_aa_ets_archiveTimestampV3.equals(unsignedAttribute.getASN1Oid())) {
			return ArchiveTimestampType.CAdES_V3;
		}
		return ArchiveTimestampType.CAdES;
	}

	@Override
	@SuppressWarnings("rawtypes")
	protected List<AdvancedSignature> getCounterSignatures(CAdESAttribute unsignedAttribute) {
		List<AdvancedSignature> cadesResult = new ArrayList<>();
		
		// unable to build a SignerInformation with BC (protected constructor)
		// extract all found CounterSignatures and compare with a found SignerInfo(s)
		List<AdvancedSignature> allCounterSignatures = signature.getCounterSignatures();
		
		ASN1Set attrValues = unsignedAttribute.getAttrValues();
		for (Enumeration en = attrValues.getObjects(); en.hasMoreElements();)
        {
            SignerInfo si = SignerInfo.getInstance(en.nextElement());
            byte[] encodedSI = DSSASN1Utils.getDEREncoded(si);
            
            for (AdvancedSignature counterSignature : allCounterSignatures) {
            	CAdESSignature cadesCounterSignature = (CAdESSignature) counterSignature;
            	SignerInfo signerInfo = cadesCounterSignature.getSignerInformation().toASN1Structure();
            	byte[] encodedSignerInfo = DSSASN1Utils.getDEREncoded(signerInfo);
            	
            	if (Arrays.equals(encodedSI, encodedSignerInfo)) {
            		cadesResult.add(counterSignature);
            	}
            }
        }
		
		return cadesResult;
	}
	
	@Override
	protected List<TimestampedReference> getCounterSignatureReferences(AdvancedSignature counterSignature) {
		/*
		 * The reason to override:
		 * CAdES counter signature does not have a private SignedData certificates/revocations
		 */
		List<TimestampedReference> counterSigReferences = new ArrayList<>();
		
		counterSigReferences.add(new TimestampedReference(counterSignature.getId(), TimestampedObjectType.SIGNATURE));
		
		List<CertificateRef> signingCertificateRefs = counterSignature.getCertificateSource().getSigningCertificateRefs();
		addReferences(counterSigReferences, createReferencesForCertificateRefs(signingCertificateRefs,
				counterSignature.getCertificateSource(), certificateSource));
		
		TimestampSource counterSignatureTimestampSource = counterSignature.getTimestampSource();
		addReferences(counterSigReferences, counterSignatureTimestampSource.getSignerDataReferences());
		addReferences(counterSigReferences, counterSignatureTimestampSource.getUnsignedPropertiesReferences());
		addReferences(counterSigReferences, getEncapsulatedReferencesFromTimestamps(
				counterSignatureTimestampSource.getAllTimestamps()));
		
		return counterSigReferences;
	}

}
