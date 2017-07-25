package eu.europa.esig.dss.signature.policy.asn1;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.SignPolExtensions;
import eu.europa.esig.dss.signature.policy.SignPolExtn;

public class ASN1SignPolExtensions extends ASN1Object implements SignPolExtensions {
	
	private List<SignPolExtn> signPolExtn = new ArrayList<SignPolExtn>();

	public static ASN1SignPolExtensions getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1SignPolExtensions(ASN1Sequence.getInstance(obj));
        }

        return null;
	}
	
	public ASN1SignPolExtensions(ASN1Sequence as) {
		for(ASN1Encodable e : as) {
			signPolExtn.add(ASN1SignPolExtn.getInstance(e));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(signPolExtn);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtensions#getSignPolExtn()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtn() {
		return signPolExtn;
	}

}
