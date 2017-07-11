package eu.europa.dss.signature.policy.asn1;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.dss.signature.policy.CertificateTrustTrees;

/**
 * CertificateTrustTrees ::=   SEQUENCE OF CertificateTrustPoint
 * @author davyd.santos
 *
 */
public class ASN1CertificateTrustTrees extends ASN1Object implements CertificateTrustTrees {
	private List<CertificateTrustPoint> certificateTrustPoints = new ArrayList<CertificateTrustPoint>();

	public static ASN1CertificateTrustTrees getInstance(ASN1Encodable obj) {
		if (obj != null) {
			return new ASN1CertificateTrustTrees(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public ASN1CertificateTrustTrees(ASN1Sequence as) {
		for (ASN1Encodable asn1Encodable : as) {
			certificateTrustPoints.add(ASN1CertificateTrustPoint.getInstance(asn1Encodable));
		}
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERSequence(certificateTrustPoints.toArray(new ASN1CertificateTrustPoint[certificateTrustPoints.size()]));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustTrees#getCertificateTrustPoints()
	 */
	@Override
	public List<CertificateTrustPoint> getCertificateTrustPoints() {
		return certificateTrustPoints;
	}

}
