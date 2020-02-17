package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.EncapsulatedCertificateTokenIdentifier;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.validation.CMSCRLSource;
import eu.europa.esig.dss.validation.CMSCertificateSource;
import eu.europa.esig.dss.validation.CMSOCSPSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampCRLSource;
import eu.europa.esig.dss.validation.timestamp.TimestampOCSPSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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

@SuppressWarnings("serial")
public class CAdESTimestampSource extends AbstractTimestampSource<CAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampSource.class);
	
	protected transient final SignerInformation signerInformation;
	
	protected transient final CMSSignedData cmsSignedData;
	protected transient final List<DSSDocument> detachedDocuments;
	
	public CAdESTimestampSource(final CAdESSignature signature, final CertificatePool certificatePool) {
		super(signature);
		this.cmsSignedData = signature.getCmsSignedData();
		this.detachedDocuments = signature.getDetachedContents();
		this.signerInformation = signature.getSignerInformation();
		this.certificatePool = certificatePool;
	}

	@Override
	protected CAdESTimestampDataBuilder getTimestampDataBuilder() {
		CadesLevelBaselineLTATimestampExtractor timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(
				cmsSignedData, certificatePool.getCertificateTokens(), getCertificates());
		return new CAdESTimestampDataBuilder(cmsSignedData, signerInformation, detachedDocuments, timestampExtractor);
	}

	@Override
	protected SignatureProperties<CAdESAttribute> getSignedSignatureProperties() {
		return CAdESSignedAttributes.build(signerInformation);
	}

	@Override
	protected SignatureProperties<CAdESAttribute> getUnsignedSignatureProperties() {
		return CAdESUnsignedAttributes.build(signerInformation);
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
	protected TimestampToken makeTimestampToken(CAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		ASN1Primitive asn1Primitive = signatureAttribute.getASN1Primitive();
		if (asn1Primitive == null) {
			return null;
		}
		try {
			return new TimestampToken(asn1Primitive.getEncoded(), timestampType, certificatePool, references, TimestampLocation.CAdES);
		} catch (Exception e) {
			throw new DSSException("Cannot create a timestamp token", e);
		}
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(CAdESAttribute signedAttribute) {
		// not applicable for CAdES, must be not executed
		throw new DSSException("Not applicable for CAdES!");
	}
	
	@Override
	protected List<TimestampedReference> getSignedDataReferences(TimestampToken timestampToken) {
		
		if (ArchiveTimestampType.CAdES_V2.equals(timestampToken.getArchiveTimestampType()) ||
				ArchiveTimestampType.CAdES.equals(timestampToken.getArchiveTimestampType())) {
			// in case of ArchiveTimestampV2 or another earlier form of archive timestamp
			// all SignedData is covered
			return getSignatureSignedDataReferences();
		}
		
		List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		
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
		List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		if (signatureCertificateSource instanceof CMSCertificateSource) {
			ASN1Sequence certsHashIndex = DSSASN1Utils.getCertificatesHashIndex(atsHashIndex);
			List<DEROctetString> certsHashList = DSSASN1Utils.getDEROctetStrings(certsHashIndex);
			for (CertificateToken certificate : signatureCertificateSource.getKeyInfoCertificates()) {
				if (isDigestValuePresent(certificate.getDigest(digestAlgorithm), certsHashList)) {
					addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
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
		List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		
		// get CRL references
		ASN1Sequence crlsHashIndex = DSSASN1Utils.getCRLHashIndex(atsHashIndex);
		List<DEROctetString> crlsHashList = DSSASN1Utils.getDEROctetStrings(crlsHashIndex);
		if (signatureCRLSource instanceof CMSCRLSource) {
			for (CRLBinary crlBinary : ((CMSCRLSource) signatureCRLSource).getSignedDataCRLIdentifiers()) {
				if (isDigestValuePresent(crlBinary.getDigestValue(digestAlgorithm), crlsHashList)) {
					addReference(references, new TimestampedReference(crlBinary.asXmlId(), TimestampedObjectType.REVOCATION));
				} else {
					LOG.warn("The CRL Token with id [{}] was not included to the message imprint of timestamp with id [{}] "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							crlBinary.asXmlId(), timestampId);
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
		List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		if (signatureOCSPSource instanceof CMSOCSPSource) {
			for (OCSPResponseBinary ocspResponse : ((CMSOCSPSource) signatureOCSPSource).getSignedDataOCSPIdentifiers()) {
				// Compute DERTaggedObject with the same algorithm how it was created
				// See: org.bouncycastle.cms.CMSUtils getOthersFromStore()
				OtherRevocationInfoFormat otherRevocationInfoFormat = new OtherRevocationInfoFormat(ocspResponse.getAsn1ObjectIdentifier(), 
						DSSASN1Utils.toASN1Primitive(ocspResponse.getBasicOCSPRespContent()));
				// false value specifies an implicit encoding method
				DERTaggedObject derTaggedObject = new DERTaggedObject(false, 1, otherRevocationInfoFormat);
				if (isDigestValuePresent(DSSUtils.digest(digestAlgorithm, DSSASN1Utils.getDEREncoded(derTaggedObject)), crlsHashList)) {
					addReference(references, new TimestampedReference(ocspResponse.asXmlId(), TimestampedObjectType.REVOCATION));
				} else {
					LOG.warn("The OCSP Token with id [{}] was not included to the message imprint of timestamp with id [{}] "
							+ "or was added to the CMS SignedData after this ArchiveTimestamp!", 
							ocspResponse.asXmlId(), timestampId);
				}
			}
		}
		return references;
	}
	
	@Override
	protected List<TimestampedReference> getSignatureSignedDataReferences() {
		List<TimestampedReference> references = new ArrayList<TimestampedReference>();
		if (signatureCertificateSource instanceof CMSCertificateSource) {
			addReferences(references, createReferencesForCertificates(signatureCertificateSource.getKeyInfoCertificates()));
		}
		if (signatureCRLSource instanceof CMSCRLSource) {
			for (CRLBinary crlBinary : ((CMSCRLSource) signatureCRLSource).getSignedDataCRLIdentifiers()) {
				addReference(references, new TimestampedReference(crlBinary.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		if (signatureOCSPSource instanceof CMSOCSPSource) {
			for (OCSPResponseBinary ocspResponse : ((CMSOCSPSource) signatureOCSPSource).getSignedDataOCSPIdentifiers()) {
				addReference(references, new TimestampedReference(ocspResponse.asXmlId(), TimestampedObjectType.REVOCATION));
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
	protected List<Digest> getCertificateRefDigests(CAdESAttribute unsignedAttribute) {
		List<Digest> digests = new ArrayList<Digest>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			OtherCertID otherCertId = OtherCertID.getInstance(seq.getObjectAt(ii));
			DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(otherCertId.getAlgorithmHash().getAlgorithm().getId());
			digests.add(new Digest(digestAlgo, otherCertId.getCertHash()));
		}
		return digests;
	}

	@Override
	protected List<Digest> getRevocationRefCRLDigests(CAdESAttribute unsignedAttribute) {
		List<Digest> digests = new ArrayList<Digest>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			final CrlOcspRef otherRefId = CrlOcspRef.getInstance(seq.getObjectAt(ii));
			final CrlListID otherCrlIds = otherRefId.getCrlids();
			if (otherCrlIds != null) {
				for (final CrlValidatedID id : otherCrlIds.getCrls()) {
					OtherHash crlHash = id.getCrlHash();
					if (crlHash != null) {
						DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(crlHash.getHashAlgorithm().getAlgorithm().getId());
						digests.add(new Digest(digestAlgo, crlHash.getHashValue()));
					}
				}
			}
		}
		return digests;
	}

	@Override
	protected List<Digest> getRevocationRefOCSPDigests(CAdESAttribute unsignedAttribute) {
		List<Digest> digests = new ArrayList<Digest>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int i = 0; i < seq.size(); i++) {
			final CrlOcspRef otherCertId = CrlOcspRef.getInstance(seq.getObjectAt(i));
			final OcspListID ocspListID = otherCertId.getOcspids();
			if (ocspListID != null) {
				for (final OcspResponsesID ocspResponsesID : ocspListID.getOcspResponses()) {
					final OtherHash ocspHash = ocspResponsesID.getOcspRepHash();
					if (ocspHash != null) {
						DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(ocspHash.getHashAlgorithm().getAlgorithm().getId());
						digests.add(new Digest(digestAlgo, ocspHash.getHashValue()));
					}
				}
			}
		}
		return digests;
	}

	@Override
	protected List<EncapsulatedCertificateTokenIdentifier> getEncapsulatedCertificateIdentifiers(CAdESAttribute unsignedAttribute) {
		List<EncapsulatedCertificateTokenIdentifier> certificateIdentifiers = new ArrayList<EncapsulatedCertificateTokenIdentifier>();
		ASN1Sequence seq = (ASN1Sequence) unsignedAttribute.getASN1Object();
		for (int ii = 0; ii < seq.size(); ii++) {
			final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
			try {
				certificateIdentifiers.add(new EncapsulatedCertificateTokenIdentifier(cs.getEncoded()));
			} catch (IOException e) {
				LOG.warn("Unable to parse encapsulated certificate : {}", e.getMessage());
			}
		}
		return certificateIdentifiers;
	}

	@Override
	protected List<CRLBinary> getEncapsulatedCRLIdentifiers(CAdESAttribute unsignedAttribute) {
		List<CRLBinary> crlBinaryIdentifiers = new ArrayList<CRLBinary>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			for (final CertificateList revValue : revocationValues.getCrlVals()) {
				try {
					crlBinaryIdentifiers.add(new CRLBinary(revValue.getEncoded()));
				} catch (IOException e) {
					LOG.warn("Unable to parse revocation value : {}", e.getMessage());
				}
			}
		}
		return crlBinaryIdentifiers;
	}

	@Override
	protected List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(CAdESAttribute unsignedAttribute) {
		List<OCSPResponseBinary> ocspIdentifiers = new ArrayList<OCSPResponseBinary>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(asn1Object);
		if (revocationValues != null) {
			for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {
				final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
				ocspIdentifiers.add(OCSPResponseBinary.build(basicOCSPResp));
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
	protected void addEncapsulatedValuesFromTimestamp(List<TimestampedReference> references, TimestampToken timestampedTimestamp) {
		super.addEncapsulatedValuesFromTimestamp(references, timestampedTimestamp);
		
		TimestampCRLSource timeStampCRLSource = timestampedTimestamp.getCRLSource();
		crlSource.addAll(timeStampCRLSource);
		for (CRLBinary crlBinary : timeStampCRLSource.getCRLBinaryList()) {
			TimestampedReference crlReference = new TimestampedReference(crlBinary.asXmlId(), TimestampedObjectType.REVOCATION);
			addReference(references, crlReference);
		}
		for (CRLRef crlRef : timeStampCRLSource.getAllCRLReferences()) {
			CRLBinary crlBinaryIdentifier = crlSource.getIdentifier(crlRef);
			if (crlBinaryIdentifier != null) {
				TimestampedReference crlReference = new TimestampedReference(crlBinaryIdentifier.asXmlId(), TimestampedObjectType.REVOCATION);
				addReference(references, crlReference);
			}
		}
		
		TimestampOCSPSource timeStampOCSPSource = timestampedTimestamp.getOCSPSource();
		ocspSource.addAll(timeStampOCSPSource);
		for (OCSPResponseBinary ocspResponse : timeStampOCSPSource.getOCSPResponsesList()) {
			TimestampedReference ocspReference = new TimestampedReference(ocspResponse.asXmlId(), TimestampedObjectType.REVOCATION);
			addReference(references, ocspReference);
		}
		for (OCSPRef ocspRef : timeStampOCSPSource.getAllOCSPReferences()) {
			OCSPResponseBinary ocspResponseIdentifier = ocspSource.getIdentifier(ocspRef);
			if (ocspResponseIdentifier != null) {
				TimestampedReference ocspReference = new TimestampedReference(ocspResponseIdentifier.asXmlId(), TimestampedObjectType.REVOCATION);
				addReference(references, ocspReference);
			}
		}
		
	}

}
