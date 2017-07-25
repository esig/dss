package eu.europa.esig.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

import eu.europa.esig.dss.signature.policy.CertRevReq;
import eu.europa.esig.dss.signature.policy.RevReq;

/**
 * CertRevReq ::= SEQUENCE {
 *         endCertRevReq   RevReq,
 *         caCerts      [0] RevReq
 *                                           }
 * @author davyd.santos
 *
 */
public class ASN1CertRevReq extends ASN1Object implements CertRevReq {
	private ASN1RevReq endCertRevReq;
	private ASN1RevReq caCerts;
	
	public static ASN1CertRevReq getInstance(ASN1Encodable e) {
		if (e != null) {
			return new ASN1CertRevReq(ASN1Sequence.getInstance(e));
		}
		
		return null;
	}
	
	public ASN1CertRevReq(ASN1Sequence as) {
		endCertRevReq = ASN1RevReq.getInstance(as.getObjectAt(0));
		caCerts = ASN1RevReq.getInstance(ASN1TaggedObject.getInstance(as.getObjectAt(1)).getObject());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(endCertRevReq, new DERTaggedObject(0, caCerts));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertRevReq#getEndCertRevReq()
	 */
	@Override
	public RevReq getEndCertRevReq() {
		return endCertRevReq;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertRevReq#getCaCerts()
	 */
	@Override
	public RevReq getCaCerts() {
		return caCerts;
	}

}
