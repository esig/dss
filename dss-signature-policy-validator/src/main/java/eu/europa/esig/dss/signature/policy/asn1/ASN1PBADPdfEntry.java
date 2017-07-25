package eu.europa.esig.dss.signature.policy.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.signature.policy.PBADPdfEntry;

public class ASN1PBADPdfEntry extends ASN1Object implements PBADPdfEntry {
	private String name;
	private byte[] value;
	
	public ASN1PBADPdfEntry(ASN1Sequence as) {
		name = DERUTF8String.getInstance(as.getObjectAt(0)).getString();
		if (as.size() > 1) {
			byte[] octets = ASN1OctetString.getInstance(as.getObjectAt(1)).getOctets();
			value = DERUTF8String.getInstance(octets).getString().getBytes();
		}
	}
	
	public ASN1PBADPdfEntry(String name) {
		if (name == null || name.trim().equals("")) {
			throw new IllegalArgumentException("Empty name is not valid");
		}
		this.name = name;
	}
	
	public ASN1PBADPdfEntry(String name, byte[] value) {
		this(name);
		this.value = value;
	}
	
	public ASN1PBADPdfEntry(String name, String value) {
		this(name, value == null? null: value.getBytes());
	}

	/* (non-Javadoc)
	 * @see eu.europa.dss.signature.policy.asn1.PBADPdfEntry#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/* (non-Javadoc)
	 * @see eu.europa.dss.signature.policy.asn1.PBADPdfEntry#getValue()
	 */
	@Override
	public byte[] getValue() {
		return value;
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		try {
			return ASN1Utils.createASN1Sequence(
					new DERUTF8String(name), 
					value == null? null: new DEROctetString(DERUTF8String.getInstance(value)));
		} catch (IOException e) {
			throw new DSSException("Error parsing PBADPdfEntry");
		}
	}
}