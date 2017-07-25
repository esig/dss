package eu.europa.esig.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.CertRevReq;
import eu.europa.esig.dss.signature.policy.CertificateTrustTrees;
import eu.europa.esig.dss.signature.policy.SigningCertTrustCondition;

/**
 * SigningCertTrustCondition ::=   SEQUENCE {
 *     signerTrustTrees              CertificateTrustTrees,
 *     signerRevReq                  CertRevReq
 *                                              }
 */
public class ASN1SigningCertTrustCondition extends ASN1Object implements SigningCertTrustCondition {
	private ASN1CertificateTrustTrees signerTrustTrees;
	private ASN1CertRevReq signerRevReq;

	public static ASN1SigningCertTrustCondition getInstance(ASN1Encodable obj) {
		if (obj != null) {
			return new ASN1SigningCertTrustCondition(ASN1Sequence.getInstance(obj));
		}
		return null;
	}
	
	public ASN1SigningCertTrustCondition(ASN1Sequence obj) {
		signerTrustTrees = ASN1CertificateTrustTrees.getInstance(obj.getObjectAt(0));
		signerRevReq = ASN1CertRevReq.getInstance(obj.getObjectAt(1));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(signerTrustTrees, signerRevReq);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SigningCertTrustCondition#getSignerTrustTrees()
	 */
	@Override
	public CertificateTrustTrees getSignerTrustTrees() {
		return signerTrustTrees;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SigningCertTrustCondition#getSignerRevReq()
	 */
	@Override
	public CertRevReq getSignerRevReq() {
		return signerRevReq;
	}

}
