/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.signerattributesV2;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Attribute;

public class SignerAttributeV2 extends ASN1Object {

	private Object[] values;

	public Object[] getValues() {
		return values;
	}

	public static SignerAttributeV2Builder builder() {
		return new SignerAttributeV2Builder();
	}

	public static SignerAttributeV2 getInstance(Object o) {
		if (o instanceof SignerAttributeV2) {
			return (SignerAttributeV2) o;
		} else if (o != null) {
			return new SignerAttributeV2(ASN1Sequence.getInstance(o));
		}

		return null;
	}

	private SignerAttributeV2(ASN1Sequence seq) {
		int size = seq.size();

		if (size > 3) {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
		int index = 0;
		values = new Object[size];

		for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
			ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

			switch (taggedObject.getTagNo()) {
			case 0:
				ASN1Sequence attrs = ASN1Sequence.getInstance(taggedObject, true);
				Attribute[] attributes = new Attribute[attrs.size()];
				for (int i = 0; i != attributes.length; i++) {
					attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
				}
				values[index] = attributes;
				break;
			case 1:
				values[index] = CertifiedAttributesV2.getInstance(ASN1Sequence.getInstance(taggedObject, true));
				break;
			case 2:
				values[index] = SignedAssertions.getInstance(ASN1Sequence.getInstance(taggedObject, true));
				break;
			default:
				throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
			}
			index++;
		}
	}

	private SignerAttributeV2(SignerAttributeV2Builder builder) {

		List<Object> objects = new ArrayList<>();

		if (!builder.claimedAttributes.isEmpty()) {
			objects.add(builder.claimedAttributes.toArray(new Attribute[builder.claimedAttributes.size()]));
		}
		if (builder.certifiedAttributes != null) {
			objects.add(builder.certifiedAttributes);
		}
		if (!builder.signedAssertions.isEmpty()) {
			objects.add(new SignedAssertions(builder.signedAssertions));
		}

		this.values = objects.toArray();
	}

	/**
	 * <pre>
	 * 		SignerAttributeV2 ::= SEQUENCE {
	 *			claimedAttributes [0] ClaimedAttributes OPTIONAL,
	 *			certifiedAttributesV2 [1] CertifiedAttributesV2 OPTIONAL,
	 *			signedAssertions [2] SignedAssertions OPTIONAL
	 *		}
	 * 
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
			}
		}

		return new DERSequence(v);
	}

	public static class SignerAttributeV2Builder {

		private List<SignedAssertion> signedAssertions = new ArrayList<SignedAssertion>();
		private List<Attribute> claimedAttributes = new ArrayList<Attribute>();
		private CertifiedAttributesV2 certifiedAttributes;

		public SignerAttributeV2Builder setClaimedAttributes(List<Attribute> claimedAttributes) {
			this.claimedAttributes = claimedAttributes;
			return this;
		}

		public SignerAttributeV2Builder addClaimedAttribute(Attribute claimedAttribute) {
			this.claimedAttributes.add(claimedAttribute);
			return this;
		}

		public SignerAttributeV2Builder setCertifiedAttributes(CertifiedAttributesV2 certifiedAttributes) {
			this.certifiedAttributes = certifiedAttributes;
			return this;
		}

		public SignerAttributeV2Builder setSignedAssertions(List<SignedAssertion> signedAssertions) {
			this.signedAssertions = signedAssertions;
			return this;
		}

		public SignerAttributeV2Builder addSignedAssertion(SignedAssertion signedAssertion) {
			this.signedAssertions.add(signedAssertion);
			return this;
		}

		public SignerAttributeV2 build() {
			return new SignerAttributeV2(this);
		}
	}

}
