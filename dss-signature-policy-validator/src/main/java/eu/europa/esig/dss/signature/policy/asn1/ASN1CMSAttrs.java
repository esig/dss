package eu.europa.esig.dss.signature.policy.asn1;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.SignatureAttrs;

public class ASN1CMSAttrs extends ASN1Object implements SignatureAttrs {
	private List<String> oids = new ArrayList<String>();
	
	public static ASN1CMSAttrs getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1CMSAttrs((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1CMSAttrs(ASN1Sequence.getInstance(obj));
        }
		return null;
	}

	public ASN1CMSAttrs(ASN1Sequence as) {
		for(ASN1Encodable e : as) {
			oids.add(ASN1ObjectIdentifier.getInstance(e).getId());
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		for(String e : oids) {
			vector.add(new ASN1ObjectIdentifier(e));
		}
		return new DERSequence(vector);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CMSAttrs#getOids()
	 */
	@Override
	public List<String> getOids() {
		return oids;
	}
}
