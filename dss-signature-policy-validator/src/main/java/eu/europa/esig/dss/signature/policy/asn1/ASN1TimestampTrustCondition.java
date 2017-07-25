package eu.europa.esig.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.NameConstraints;

import eu.europa.esig.dss.signature.policy.CertRevReq;
import eu.europa.esig.dss.signature.policy.CertificateTrustTrees;
import eu.europa.esig.dss.signature.policy.DeltaTime;
import eu.europa.esig.dss.signature.policy.TimestampTrustCondition;

/**
 * TimestampTrustCondition ::= SEQUENCE {
 *     ttsCertificateTrustTrees    [0]     CertificateTrustTrees
 *                                            OPTIONAL,
 *     ttsRevReq                   [1]             CertRevReq
 *                                            OPTIONAL,
 *     ttsNameConstraints          [2]             NameConstraints
 *                                            OPTIONAL,
 *     cautionPeriod               [3]             DeltaTime
 *                                            OPTIONAL,
 *     signatureTimestampDelay     [4]             DeltaTime
 *                                            OPTIONAL }
 * @author davyd.santos
 *
 */
public class ASN1TimestampTrustCondition extends ASN1Object implements TimestampTrustCondition {
	
	private ASN1CertificateTrustTrees ttsCertificateTrustTrees;
	private ASN1CertRevReq ttsRevReq;
	private NameConstraints ttsNameConstraints;     
	private ASN1DeltaTime cautionPeriod;
	private ASN1DeltaTime signatureTimestampDelay;
	
	public static ASN1TimestampTrustCondition getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1TimestampTrustCondition(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1TimestampTrustCondition(ASN1Sequence as) {
		int index = 0;
		ASN1TaggedObject asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 0) {
			ttsCertificateTrustTrees = ASN1CertificateTrustTrees.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 1) {
			ttsRevReq = ASN1CertRevReq.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 2) {
			ttsNameConstraints = NameConstraints.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 3) {
			cautionPeriod = ASN1DeltaTime.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 5) {
			signatureTimestampDelay = ASN1DeltaTime.getInstance(asn1TaggedObject.getObject());
			
			index++;
		}
		if (as.size() > index) {
			throw new IllegalArgumentException("Unkown content found");
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(ttsCertificateTrustTrees, ttsRevReq, ttsNameConstraints, cautionPeriod, signatureTimestampDelay);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.TimestampTrustCondition#getTtsCertificateTrustTrees()
	 */
	@Override
	public CertificateTrustTrees getTtsCertificateTrustTrees() {
		return ttsCertificateTrustTrees;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.TimestampTrustCondition#getTtsRevReq()
	 */
	@Override
	public CertRevReq getTtsRevReq() {
		return ttsRevReq;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.TimestampTrustCondition#getTtsNameConstraints()
	 */
	@Override
	public NameConstraints getTtsNameConstraints() {
		return ttsNameConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.TimestampTrustCondition#getCautionPeriod()
	 */
	@Override
	public DeltaTime getCautionPeriod() {
		return cautionPeriod;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.TimestampTrustCondition#getSignatureTimestampDelay()
	 */
	@Override
	public DeltaTime getSignatureTimestampDelay() {
		return signatureTimestampDelay;
	}

}
