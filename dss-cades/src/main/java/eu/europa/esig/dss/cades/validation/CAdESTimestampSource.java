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
package eu.europa.esig.dss.cades.validation;

import static eu.europa.esig.dss.spi.OID.attributeCertificateRefsOid;
import static eu.europa.esig.dss.spi.OID.attributeRevocationRefsOid;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
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

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSException;
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
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CMSCRLSource;
import eu.europa.esig.dss.validation.CMSCertificateSource;
import eu.europa.esig.dss.validation.CMSOCSPSource;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampCRLSource;
import eu.europa.esig.dss.validation.timestamp.TimestampOCSPSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

@SuppressWarnings("serial")
public class CAdESTimestampSource extends AbstractTimestampSource<CAdESSignature, CAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampSource.class);
	
	public CAdESTimestampSource(final CAdESSignature signature) {
		super(signature);
	}

	@Override
	protected CAdESTimestampDataBuilder getTimestampDataBuilder() {
		CadesLevelBaselineLTATimestampExtractor timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(
				signature.getCmsSignedData(), certificateSource.getAllCertificateTokens());
		return new CAdESTimestampDataBuilder(signature.getCmsSignedData(), signature.getSignerInformation(), 
				signature.getDetachedContents(), timestampExtractor);
	}

	@Override
	protected SignatureProperties<CAdESAttribute> getSignedSignatureProperties() {
		return CAdESSignedAttributes.build(signature.getSignerInformation());
	}

	@Override
	protected SignatureProperties<CAdESAttribute> getUnsignedSignatureProperties() {
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
	protected boolean isPreviousDataArchiveTimestamp(CAdESAttribute unsignedAttribute) {
		// not applicable for CAdES
		return false;
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
	protected TimestampToken makeTimestampToken(CAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		TimeStampToken timestamp = signatureAttribute.toTimeStampToken();
		if (timestamp == null) {
			return null;
		}
		return new TimestampToken(timestamp, timestampType, references, TimestampLocation.CAdES);
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(CAdESAttribute signedAttribute) {
		// not applicable for CAdES, must be not executed
		throw new DSSException("Not applicable for CAdES!");
	}
	
	@Override
	protected List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken) {
		return getSignedDataReferences(timestampToken);
	}
	
	protected List<TimestampedReference> getSignedDataReferences(TimestampToken timestampToken) {
		
		if (ArchiveTimestampType.CAdES_V2.equals(timestampToken.getArchiveTimestampType()) ||
				ArchiveTimestampType.CAdES.equals(timestampToken.getArchiveTimestampType())) {
			// in case of ArchiveTimestampV2 or another earlier form of archive timestamp
			// all SignedData is covered
			return getSignatureSignedDataReferences();
		}
		
		List<TimestampedReference> references = new ArrayList<>();
		
		// Compare values present in the timestamp's Hash Index Table with signature's SignedData item digests
		final ASN1Sequence atsHashIndex = DSSASN1Utils.getAtsHashIndex(timestampToken.getUnsignedAttributes());
		if (atsHashIndex != null) {
			final DigestAlgorithm digestAlgorithm = getHashIndexDigestAlgorithm(atsHashIndex);
			
			List<TimestampedReference> certificateReferences = getSignedDataCertificateReferences(
					atsHashIndex, digestAlgorithm, timestampToken.getDSSIdAsString());
			references.addAll(certificateReferences);
	
			List<TimestampedReference> revocationReferences = getSignedDataRevocationReferences(atsHashIndex, digestAlgorithm, timestampToken.getDSSIdAsString());
			references.addAll(revocationReferences);
		}
		
		return references;
	}
	
	private List<TimestampedReference> getSignedDataCertificateReferences(final ASN1Sequence atsHashIndex, final DigestAlgorithm digestAlgorithm,
			final String timestampId) {
		List<TimestampedReference> references = new ArrayList<>();
		
		SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
		if (signatureCertificateSource instanceof CMSCertificateSource) {
			ASN1Sequence certsHashIndex = DSSASN1Utils.getCertificatesHashIndex(atsHashIndex);
			List<DEROctetString> certsHashList = DSSASN1Utils.getDEROctetStrings(certsHashIndex);
			for (CertificateToken certificate : signatureCertificateSource.getSignedDataCertificates()) {
				if (isDigestValuePresent(certificate.getDigest(digestAlgorithm), certsHashList)) {
					addReference(references, certificate.getDSSId(), TimestampedObjectType.CERTIFICATE);
				} else {
					LOG.warn("The certificate with id [{}] was not included to the message imprint of timestamp with id [{}] "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							certificate.getDSSIdAsString(), timestampId);
				}
			}
		}
		return references;
	}
	
	private List<TimestampedReference> getSignedDataRevocationReferences(final ASN1Sequence atsHashIndex, final DigestAlgorithm digestAlgorithm,
			final String timestampId) {
		List<TimestampedReference> references = new ArrayList<>();
		
		// get CRL references
		ASN1Sequence crlsHashIndex = DSSASN1Utils.getCRLHashIndex(atsHashIndex);
		List<DEROctetString> crlsHashList = DSSASN1Utils.getDEROctetStrings(crlsHashIndex);
		
		OfflineCRLSource signatureCRLSource = signature.getCRLSource();
		if (signatureCRLSource instanceof CMSCRLSource) {
			CMSCRLSource cmsCRLSource = (CMSCRLSource) signatureCRLSource;
			for (EncapsulatedRevocationTokenIdentifier<CRL> token : cmsCRLSource.getCMSSignedDataRevocationBinaries()) {
				if (isDigestValuePresent(token.getDigestValue(digestAlgorithm), crlsHashList)) {
					addReference(references, token, TimestampedObjectType.REVOCATION);
				} else {
					LOG.warn("The CRL Token with id [{}] was not included to the message imprint of timestamp with id [{}] "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							token.asXmlId(), timestampId);
				}
			}
		}

		// get OCSP references
		List<TimestampedReference> ocspReferences = getSignedDataOCSPReferences(crlsHashList, digestAlgorithm, timestampId);
		references.addAll(ocspReferences);
		
		return references;
	}
	
	private List<TimestampedReference> getSignedDataOCSPReferences(List<DEROctetString> crlsHashList, final DigestAlgorithm digestAlgorithm,
			final String timestampId) {
		List<TimestampedReference> references = new ArrayList<>();
		
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
					addReference(references, binary, TimestampedObjectType.REVOCATION);
				} else {
					LOG.warn("The OCSP Token with id [{}] was not included to the message imprint of timestamp with id [{}] "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							binary.asXmlId(), timestampId);
				}
			}
		}
		return references;
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
			for (EncapsulatedRevocationTokenIdentifier<CRL> token : ((CMSCRLSource) signatureCRLSource).getCMSSignedDataRevocationBinaries()) {
				addReference(references, token, TimestampedObjectType.REVOCATION);
			}
		}
		
		OfflineOCSPSource signatureOCSPSource = signature.getOCSPSource();
		if (signatureOCSPSource instanceof CMSOCSPSource) {
			for (EncapsulatedRevocationTokenIdentifier<OCSP> token : ((CMSOCSPSource) signatureOCSPSource).getCMSSignedDataRevocationBinaries()) {
				addReference(references, token, TimestampedObjectType.REVOCATION);
			}
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
	protected List<Identifier> getEncapsulatedCRLIdentifiers(CAdESAttribute unsignedAttribute) {
		List<Identifier> crlBinaryIdentifiers = new ArrayList<>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			for (final CertificateList revValue : revocationValues.getCrlVals()) {
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
	protected List<Identifier> getEncapsulatedOCSPIdentifiers(CAdESAttribute unsignedAttribute) {
		List<Identifier> ocspIdentifiers = new ArrayList<>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {
				try {
					final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
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
	protected void addEncapsulatedValuesFromTimestamp(List<TimestampedReference> references,
			TimestampToken timestampedTimestamp) {
		super.addEncapsulatedValuesFromTimestamp(references, timestampedTimestamp);

		TimestampCRLSource timeStampCRLSource = timestampedTimestamp.getCRLSource();
		for (EncapsulatedRevocationTokenIdentifier<CRL> binary : timeStampCRLSource.getAllRevocationBinaries()) {
			addReference(references, binary, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<CRL> binary : timeStampCRLSource.getAllReferencedRevocationBinaries()) {
			addReference(references, binary, TimestampedObjectType.REVOCATION);
		}

		TimestampOCSPSource timeStampOCSPSource = timestampedTimestamp.getOCSPSource();
		for (EncapsulatedRevocationTokenIdentifier<OCSP> binary : timeStampOCSPSource.getAllReferencedRevocationBinaries()) {
			addReference(references, binary, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<OCSP> binary : timeStampOCSPSource.getAllReferencedRevocationBinaries()) {
			addReference(references, binary, TimestampedObjectType.REVOCATION);
		}

	}

	@Override
	protected AdvancedSignature getCounterSignature(CAdESAttribute unsignedAttribute) {
		// TODO : implement within DSS-2180
		return null;
	}

}
