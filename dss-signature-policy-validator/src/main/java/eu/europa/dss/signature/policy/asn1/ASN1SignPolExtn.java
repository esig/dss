package eu.europa.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import eu.europa.dss.signature.policy.SignPolExtn;

/**
 * 
 * SignPolExtn ::= SEQUENCE {
 *  extnID OBJECT IDENTIFIER,
 *  extnValue OCTET STRING } 
 * @author davyd.santos
 *
 */
public class ASN1SignPolExtn extends ASN1Object implements SignPolExtn {
	private String extnID;
	private byte[] extnValue;

	public static ASN1SignPolExtn getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SignPolExtn((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SignPolExtn(ASN1Sequence.getInstance(obj));
        }

        return null;
	}
	
	public ASN1SignPolExtn(ASN1Sequence as) {
		if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		extnID = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0)).getId();
		extnValue = ASN1OctetString.getInstance(as.getObjectAt(1)).getOctets();
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(new ASN1ObjectIdentifier(extnID), new DEROctetString(extnValue));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtn#getExtnID()
	 */
	@Override
	public String getExtnID() {
		return extnID;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtn#getExtnValue()
	 */
	@Override
	public byte[] getExtnValue() {
		return extnValue;
	}

}
