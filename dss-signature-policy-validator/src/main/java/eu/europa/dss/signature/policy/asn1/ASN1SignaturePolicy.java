package eu.europa.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import eu.europa.dss.signature.policy.SignPolicyInfo;
import eu.europa.dss.signature.policy.SignaturePolicy;
/**
 * 
 * SignaturePolicy ::= SEQUENCE {
 *  signPolicyHashAlg AlgorithmIdentifier,
 *  signPolicyInfo SignPolicyInfo,
 *  signPolicyHash SignPolicyHash OPTIONAL } 
 * @author davyd.santos
 *
 */
public class ASN1SignaturePolicy extends ASN1Object implements SignaturePolicy {
	private AlgorithmIdentifier signPolicyHashAlg;
	private ASN1SignPolicyInfo signPolicyInfo;
	private byte[] signPolicyHash;
	
	public static ASN1SignaturePolicy getInstance(ASN1Object obj) {
		if (obj != null) {
            return new ASN1SignaturePolicy(ASN1Sequence.getInstance(obj));
        }

        return null;
	}

	public ASN1SignaturePolicy(ASN1Sequence as) {
        if (!(as.size() == 2 || as.size() == 3)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
        signPolicyHashAlg = AlgorithmIdentifier.getInstance(as.getObjectAt(0));
        signPolicyInfo = ASN1SignPolicyInfo.getInstance(as.getObjectAt(1));
        if (as.size() == 3) {
        	signPolicyHash = DEROctetString.getInstance(as.getObjectAt(2)).getOctets();
        }
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(signPolicyHashAlg);
		entries.add(signPolicyInfo);
		if (signPolicyHash != null) {
			entries.add(new DEROctetString(signPolicyHash));			
		}
		return new DERSequence(entries);
	}
	
	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyHashAlg()
	 */
	@Override
	public AlgorithmIdentifier getSignPolicyHashAlg() {
		return signPolicyHashAlg;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyInfo()
	 */
	@Override
	public SignPolicyInfo getSignPolicyInfo() {
		return signPolicyInfo;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyHash()
	 */
	@Override
	public byte[] getSignPolicyHash() {
		return signPolicyHash;
	}
}
