package eu.europa.esig.dss;

import javax.security.auth.x500.X500Principal;

import port.org.bouncycastle.asn1.ASN1Encodable;
import port.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import port.org.bouncycastle.asn1.ASN1Sequence;
import port.org.bouncycastle.asn1.DERBMPString;
import port.org.bouncycastle.asn1.DERIA5String;
import port.org.bouncycastle.asn1.DERPrintableString;
import port.org.bouncycastle.asn1.DERT61String;
import port.org.bouncycastle.asn1.DERT61UTF8String;
import port.org.bouncycastle.asn1.DERUTF8String;
import port.org.bouncycastle.asn1.DLSequence;
import port.org.bouncycastle.asn1.DLSet;

public final class Normalizer {

	public static X500Principal getNormalizedX500Principal(X500Principal x500Principal) {
		String utf8Name = getUtf8String(x500Principal);
		X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}

	public static String getUtf8String(final X500Principal x500Principal) {

		final byte[] encoded = x500Principal.getEncoded();
		final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(encoded);
		final ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
		final StringBuilder stringBuilder = new StringBuilder();
		/**
		 * RFC 4514 LDAP: Distinguished Names
		 * 2.1. Converting the RDNSequence
		 * If the RDNSequence is an empty sequence, the result is the empty or
		 * zero-length string.
		 * Otherwise, the output consists of the string encodings of each
		 * RelativeDistinguishedName in the RDNSequence (according to Section
		 * 2.2), starting with the last element of the sequence and moving
		 * backwards toward the first.
		 * ...
		 */
		for (int ii = asn1Encodables.length - 1; ii >= 0; ii--) {

			final ASN1Encodable asn1Encodable = asn1Encodables[ii];

			final DLSet dlSet = (DLSet) asn1Encodable;
			for (int jj = 0; jj < dlSet.size(); jj++) {

				final DLSequence dlSequence = (DLSequence) dlSet.getObjectAt(jj);
				if (dlSequence.size() != 2) {

					throw new DSSException("The DLSequence must contains exactly 2 elements.");
				}
				final ASN1Encodable attributeType = dlSequence.getObjectAt(0);
				final ASN1Encodable attributeValue = dlSequence.getObjectAt(1);
				String string = getString(attributeValue);

				/**
				 * RFC 4514               LDAP: Distinguished Names
				 * ...
				 * Other characters may be escaped.
				 *
				 * Each octet of the character to be escaped is replaced by a backslash
				 * and two hex digits, which form a single octet in the code of the
				 * character.  Alternatively, if and only if the character to be escaped
				 * is one of
				 *
				 * ' ', '"', '#', '+', ',', ';', '<', '=', '>', or '\'
				 * (U+0020, U+0022, U+0023, U+002B, U+002C, U+003B,
				 * U+003C, U+003D, U+003E, U+005C, respectively)
				 *
				 * it can be prefixed by a backslash ('\' U+005C).
				 * ...
				 */
				string = string.replace("\"", "\\\"");
				string = string.replace("#", "\\#");
				string = string.replace("+", "\\+");
				string = string.replace(",", "\\,");
				string = string.replace(";", "\\;");
				string = string.replace("<", "\\<");
				string = string.replace("=", "\\=");
				string = string.replace(">", "\\>");
				// System.out.println(">>> " + attributeType.toString() + "=" + attributeValue.getClass().getSimpleName() + "[" + string + "]");
				if (stringBuilder.length() != 0) {
					stringBuilder.append(',');
				}
				stringBuilder.append(attributeType).append('=').append(string);
			}
		}
		//final X500Name x500Name = X500Name.getInstance(encoded);
		return stringBuilder.toString();
	}

	private static String getString(ASN1Encodable attributeValue) {
		String string;
		if (attributeValue instanceof DERUTF8String) {
			string = ((DERUTF8String) attributeValue).getString();
		} else if (attributeValue instanceof DERPrintableString) {
			string = ((DERPrintableString) attributeValue).getString();
		} else if (attributeValue instanceof DERBMPString) {
			string = ((DERBMPString) attributeValue).getString();
		} else if (attributeValue instanceof DERT61String) {
			string = ((DERT61String) attributeValue).getString();
		} else if (attributeValue instanceof DERIA5String) {
			string = ((DERIA5String) attributeValue).getString();
		} else if (attributeValue instanceof ASN1ObjectIdentifier) {
			string = ((ASN1ObjectIdentifier) attributeValue).getId();
		} else if (attributeValue instanceof DERT61UTF8String) {
			string = ((DERT61UTF8String) attributeValue).getString();
		} else if (attributeValue instanceof DLSequence) {
			StringBuffer buffer = new StringBuffer();
			DLSequence sequence = (DLSequence) attributeValue;
			for(int i = 0; i<sequence.size(); i++) {
				buffer.append(getString(sequence.getObjectAt(1)));
			}
			string = buffer.toString();
		} else {
			throw new DSSException("Unknown encoding ; " + attributeValue.getClass().getSimpleName());
		}
		return string;
	}

}
