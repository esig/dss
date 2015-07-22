package port.org.bouncycastle.asn1;

import java.io.IOException;

import port.org.bouncycastle.util.Arrays;
import port.org.bouncycastle.util.Strings;

public class DERGeneralString extends ASN1Primitive implements ASN1String {

	private byte[] string;

	public static DERGeneralString getInstance(Object obj) {
		if ((obj == null) || (obj instanceof DERGeneralString)) {
			return (DERGeneralString) obj;
		}

		if (obj instanceof byte[]) {
			try {
				return (DERGeneralString) fromByteArray((byte[]) obj);
			} catch (Exception e) {
				throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
			}
		}

		throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
	}

	public static DERGeneralString getInstance(ASN1TaggedObject obj, boolean explicit) {
		ASN1Primitive o = obj.getObject();

		if (explicit || (o instanceof DERGeneralString)) {
			return getInstance(o);
		} else {
			return new DERGeneralString(((ASN1OctetString) o).getOctets());
		}
	}

	DERGeneralString(byte[] string) {
		this.string = string;
	}

	public DERGeneralString(String string) {
		this.string = Strings.toByteArray(string);
	}

	@Override
	public String getString() {
		return Strings.fromByteArray(string);
	}

	@Override
	public String toString() {
		return getString();
	}

	public byte[] getOctets() {
		return Arrays.clone(string);
	}

	@Override
	boolean isConstructed() {
		return false;
	}

	@Override
	int encodedLength() {
		return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
	}

	@Override
	void encode(ASN1OutputStream out) throws IOException {
		out.writeEncoded(BERTags.GENERAL_STRING, string);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(string);
	}

	@Override
	boolean asn1Equals(ASN1Primitive o) {
		if (!(o instanceof DERGeneralString)) {
			return false;
		}
		DERGeneralString s = (DERGeneralString) o;

		return Arrays.areEqual(string, s.string);
	}

}
