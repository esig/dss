package eu.europa.dss.signature.policy.asn1;

import static eu.europa.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.dss.signature.policy.asn1.ASN1Utils.integer;
import static eu.europa.dss.signature.policy.asn1.ASN1Utils.tag;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.dss.signature.policy.PolicyConstraints;

/**
 * PolicyConstraints ::= SEQUENCE {
 *         requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *         inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 * 
 * SkipCerts ::= INTEGER (0..MAX)
 * @author davyd.santos
 *
 */
public class ASN1PolicyConstraints extends ASN1Object implements PolicyConstraints {
	private Integer requireExplicitPolicy;
	private Integer inhibitPolicyMapping;

	public static ASN1PolicyConstraints getInstance(ASN1Encodable obj) {
		if (obj != null) {
			return new ASN1PolicyConstraints(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public ASN1PolicyConstraints(ASN1Sequence as) {
		if (as.size() == 0) {
			return;
		}
		
		ASN1Encodable obj = as.getObjectAt(0);
		requireExplicitPolicy = ASN1Utils.getTagEnumeratedValue(obj, 0);
		
		if (as.size() > 1) {
			obj = as.getObjectAt(1);
		}
		inhibitPolicyMapping = ASN1Utils.getTagEnumeratedValue(obj, 1);
		if (as.size() > 2) {
			throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				tag(0, integer(requireExplicitPolicy)),
				tag(1, integer(inhibitPolicyMapping))
				);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.PolicyConstraints#getRequireExplicitPolicy()
	 */
	@Override
	public Integer getRequireExplicitPolicy() {
		return requireExplicitPolicy;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.PolicyConstraints#getInhibitPolicyMapping()
	 */
	@Override
	public Integer getInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}

}
