/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Enumeration;

/**
 * Basic support of ETSI EN 319 122-1 V1.1.1 chapter 5.2.6.1
 * 
 * Based on org.bouncycastle.asn1.esf.SignerAttribute
 * 
 * Note : signedAssertions are not supported
 * 
 * Quote ETSI : The definition of specific signedAssertions is outside of the scope of the present document
 */
public class SignerAttributeV2 extends ASN1Object {

	private static final Logger LOG = LoggerFactory.getLogger(SignerAttributeV2.class);

	/** Array of signed attributes */
	private Object[] values;

	/**
	 * Parses the object and returns instance of {@code SignerAttributeV2},
	 * null if the object has another type
	 *
	 * @param o object representing the {@link SignerAttributeV2}
	 * @return {@link SignerAttributeV2}
	 */
	public static SignerAttributeV2 getInstance(Object o) {
		if (o instanceof SignerAttributeV2) {
			return (SignerAttributeV2) o;
		} else if (o != null) {
			return new SignerAttributeV2(ASN1Sequence.getInstance(o));
		}

		return null;
	}

	@SuppressWarnings("rawtypes")
	private SignerAttributeV2(ASN1Sequence seq) {
		int index = 0;
		values = new Object[seq.size()];

		for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
			ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

			if (taggedObject.getTagNo() == 0) {
				ASN1Sequence attrs = ASN1Sequence.getInstance(taggedObject, true);
				Attribute[] attributes = new Attribute[attrs.size()];

				for (int i = 0; i != attributes.length; i++) {
					attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
				}
				values[index] = attributes;
			} else if (taggedObject.getTagNo() == 1) {
				values[index] = CertifiedAttributesV2.getInstance(ASN1Sequence.getInstance(taggedObject, true));
			} else if (taggedObject.getTagNo() == 2) {
			    	LOG.info("SAML assertion detected");
				values[index] = SignedAssertions.getInstance(ASN1Sequence.getInstance(taggedObject, true));
			} else {
				throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
			}
			index++;
		}
	}

	/**
	 * Creates a {@code SignerAttributeV2} from an array of {@code claimedAttributes}
	 *
	 * @param claimedAttributes array of {@link Attribute}s
	 */
	public SignerAttributeV2(Attribute[] claimedAttributes) {
		this.values = new Object[1];
		this.values[0] = claimedAttributes;
	}

	/**
	 * Creates a {@code SignerAttributeV2} from {@code certifiedAttributes}
	 *
	 * @param certifiedAttributes {@link CertifiedAttributesV2}s
	 */
	public SignerAttributeV2(CertifiedAttributesV2 certifiedAttributes) {
		this.values = new Object[1];
		this.values[0] = certifiedAttributes;
	}

	/**
	 * Creates a {@code SignerAttributeV2} from {@code signedAssertions}
	 *
	 * @param signedAssertions {@link SignedAssertions}s
	 */
	public SignerAttributeV2(SignedAssertions signedAssertions) {
		this.values = new Object[1];
		this.values[0] = signedAssertions;
	}

	/**
	 * Return the sequence of choices - the array elements will either be of
	 * type Attribute[] or AttributeCertificate depending on what tag was used.
	 *
	 * @return array of choices.
	 */
	public Object[] getValues() {
		Object[] rv = new Object[values.length];

		System.arraycopy(values, 0, rv, 0, rv.length);

		return rv;
	}

	/**
	 * <pre>
	 *  SignerAttributeV2 ::= SEQUENCE {
	 *	 	claimedAttributes [0] ClaimedAttributes OPTIONAL,
	 * 		certifiedAttributesV2 [1] CertifiedAttributesV2 OPTIONAL,
	 * 		signedAssertions [2] SignedAssertions OPTIONAL
	 *	}
	 * </pre>
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		for (int i = 0; i != values.length; i++) {
			if (values[i] instanceof Attribute[]) {
				v.add(new DERTaggedObject(0, new DERSequence((Attribute[]) values[i])));
			} else if (values[i] instanceof CertifiedAttributesV2) {
				v.add(new DERTaggedObject(1, (CertifiedAttributesV2) values[i]));
			} else if (values[i] instanceof SignedAssertions) {
				v.add(new DERTaggedObject(2, (SignedAssertions) values[i]));
			} else {
				LOG.warn("Unsupported type {}", values[i]);
			}
		}

		return new DERSequence(v);
	}

}
