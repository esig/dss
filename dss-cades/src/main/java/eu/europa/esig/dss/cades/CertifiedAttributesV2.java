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
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Enumeration;

/**
 * Basic support of ETSI EN 319 122-1 V1.1.1 chapter 5.2.6.1
 * 
 * <pre>
 * 	CertifiedAttributesV2 ::= SEQUENCE OF CHOICE {
 * 		attributeCertificate [0] AttributeCertificate,
 * 		otherAttributeCertificate [1] OtherAttributeCertificate
 *	}
 * </pre>
 * 
 * Note : OtherAttributeCertificate is not supported.
 * Quote ETSI : The definition of specific otherAttributeCertificates is outside of the scope of the present document.
 */
public class CertifiedAttributesV2 extends ASN1Object {

	private static final Logger LOG = LoggerFactory.getLogger(CertifiedAttributesV2.class);

	/** Cached array of {@code AttributeCertificate} objects */
	private Object[] values;

	/**
	 * Parses and returns {@code CertifiedAttributesV2} from the given object
	 *
	 * @param o object representing {@link CertifiedAttributesV2}
	 * @return {@link CertifiedAttributesV2}
	 */
	public static CertifiedAttributesV2 getInstance(Object o) {
		if (o instanceof CertifiedAttributesV2) {
			return (CertifiedAttributesV2) o;
		} else if (o != null) {
			return new CertifiedAttributesV2(ASN1Sequence.getInstance(o));
		}

		return null;
	}

	@SuppressWarnings("rawtypes")
	private CertifiedAttributesV2(ASN1Sequence seq) {
		int index = 0;
		values = new Object[seq.size()];

		for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
			ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

			if (taggedObject.getTagNo() == 0) {
				values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
			} else if (taggedObject.getTagNo() == 1) {
				LOG.info("OtherAttributeCertificate detected");
			} else {
				throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
			}
			index++;
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (int i = 0; i != values.length; i++) {
			if (values[i] instanceof AttributeCertificate) {
				v.add(new DERTaggedObject(0, (AttributeCertificate) values[i]));
			} else {
				LOG.warn("Unsupported type : {}", values[i]);
			}
		}
		return new DERSequence(v);
	}

}
