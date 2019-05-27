package eu.europa.esig.dss.cades.validation;

import static eu.europa.esig.dss.OID.attributeCertificateRefsOid;
import static eu.europa.esig.dss.OID.attributeRevocationRefsOid;
import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncapsulatedCertificateTokenIdentifier;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.TimestampLocation;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseIdentifier;

public class CAdESTimestampSource extends AbstractTimestampSource<CAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampSource.class);
	
	private final SignerInformation signerInformation;
	
	public CAdESTimestampSource(final SignerInformation signerInformation, final CertificatePool certificatePool) {
		super(certificatePool);
		this.signerInformation = signerInformation;
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
		return id_aa_ets_archiveTimestampV2.equals(unsignedAttribute.getASN1Oid()) || id_aa_ets_archiveTimestampV3.equals(unsignedAttribute.getASN1Oid()) ;
	}

	@Override
	protected boolean isTimeStampValidationData(CAdESAttribute unsignedAttribute) {
		// not applicable for CAdES
		return false;
	}
	
	@Override
	protected TimestampToken makeTimestampToken(CAdESAttribute signatureAttribute, TimestampType timestampType) {
		ASN1Primitive asn1Primitive = signatureAttribute.getASN1Primitive();
		if (asn1Primitive == null) {
			return null;
		}
		try {
			return new TimestampToken(asn1Primitive.getEncoded(), timestampType, certificatePool, TimestampLocation.CAdES);
		} catch (Exception e) {
			throw new DSSException("Cannot create a timestamp token", e);
		}
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(List<TimestampInclude> includes) {
		// not applicable for CAdES, must be not executed
		throw new DSSException("Not applicable for CAdES!");
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
	protected List<CRLBinaryIdentifier> getEncapsulatedCRLIdentifiers(CAdESAttribute unsignedAttribute) {
		List<CRLBinaryIdentifier> crlBinaryIdentifiers = new ArrayList<CRLBinaryIdentifier>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		final RevocationValues revValues = RevocationValues.getInstance(asn1Object);
		for (final CertificateList revValue : revValues.getCrlVals()) {
			try {
				crlBinaryIdentifiers.add(CRLBinaryIdentifier.build(revValue.getEncoded(), RevocationOrigin.INTERNAL_REVOCATION_VALUES));
			} catch (IOException e) {
				LOG.warn("Unable to parse revocation value : {}", e.getMessage());
			}
		}
		return crlBinaryIdentifiers;
	}

	@Override
	protected List<OCSPResponseIdentifier> getEncapsulatedOCSPIdentifiers(CAdESAttribute unsignedAttribute) {
		List<OCSPResponseIdentifier> ocspIdentifiers = new ArrayList<OCSPResponseIdentifier>();
		ASN1Encodable asn1Object = unsignedAttribute.getASN1Object();
		final RevocationValues revocationValues = RevocationValues.getInstance(asn1Object);
		for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {
			final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
			ocspIdentifiers.add(OCSPResponseIdentifier.build(basicOCSPResp, RevocationOrigin.INTERNAL_REVOCATION_VALUES));
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

}
