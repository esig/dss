package eu.europa.dss.signature.policy.asn1;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.dss.signature.policy.SignPolExtn;
import eu.europa.dss.signature.policy.VerifierRules;

/**
 * VerifierRules ::= SEQUENCE {
 * 	 mandatedUnsignedAttr MandatedUnsignedAttr,
 * 	 signPolExtensions SignPolExtensions OPTIONAL
 * 	 }
 */ 
public class ASN1VerifierRules extends ASN1Object implements VerifierRules {
	private ASN1CMSAttrs mandatedUnsignedAttr;
	private ASN1SignPolExtensions signPolExtensions;

	public static ASN1VerifierRules getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1VerifierRules(ASN1Sequence.getInstance(obj));
        }
		return null;
	}

	public ASN1VerifierRules(ASN1Sequence as) {
		int index = 0;
		if (!(as.size() == 1 || as.size() == 2)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		mandatedUnsignedAttr = ASN1CMSAttrs.getInstance(as.getObjectAt(index++));
		if (as.size() > 1) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(as.getObjectAt(index++));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(mandatedUnsignedAttr);
		if (signPolExtensions != null) {
			entries.add(signPolExtensions);			
		}
		return new DERSequence(entries);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.VerifierRules#getMandatedUnsignedAttr()
	 */
	@Override
	public List<String> getMandatedUnsignedAttr() {
		return mandatedUnsignedAttr.getOids();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.VerifierRules#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions.getSignPolExtn();
	}

}
