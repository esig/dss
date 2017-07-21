package eu.europa.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;

public class ASN1PBADPdfEntry extends ASN1Object {
	private String name;
	private byte[] value;
	
	public ASN1PBADPdfEntry(ASN1Sequence as) {
		name = DERUTF8String.getInstance(as.getObjectAt(0)).getString();
		if (as.size() > 1) {
			value = ASN1OctetString.getInstance(as.getObjectAt(1)).getOctets();
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

	public String getName() {
		return name;
	}

	public byte[] getValue() {
		return value;
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(
				new DERUTF8String(name), 
				value == null? null: new DEROctetString(value));
	}
}