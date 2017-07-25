package eu.europa.esig.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.esig.dss.signature.policy.SignerRules;
import eu.europa.esig.dss.signature.policy.VerifierRules;

/**
 * SignerAndVerifierRules ::= SEQUENCE {
 *  signerRules SignerRules,
 *  verifierRules VerifierRules } 
 * @author davyd.santos
 *
 */
public class ASN1SignerAndVeriferRules extends ASN1Object implements SignerAndVerifierRules {
	private ASN1SignerRules signerRules;
	private ASN1VerifierRules verifierRules;

	public static ASN1SignerAndVeriferRules getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SignerAndVeriferRules((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SignerAndVeriferRules(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1SignerAndVeriferRules(ASN1Sequence as) {
		if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		signerRules = ASN1SignerRules.getInstance(as.getObjectAt(0));
		verifierRules = ASN1VerifierRules.getInstance(as.getObjectAt(1));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(signerRules);
		entries.add(verifierRules);

		return new DERSequence(entries);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerAndVerifierRules#getSignerRules()
	 */
	@Override
	public SignerRules getSignerRules() {
		return signerRules;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerAndVerifierRules#getVerifierRules()
	 */
	@Override
	public VerifierRules getVerifierRules() {
		return verifierRules;
	}

}
