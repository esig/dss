/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.asn1;

import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class ASN1Utils {

	public static Integer getTagEnumeratedValue(ASN1Encodable obj, int tagNo) {
		ASN1Primitive asn = getTagValue(obj, tagNo);
		return asn != null && asn instanceof ASN1Enumerated ? ((ASN1Enumerated) asn).getValue().intValue(): null;
	}

	public static ASN1Primitive getTagValue(ASN1Encodable obj, int tagNo) {
		if (obj == null || !(obj instanceof ASN1TaggedObject)) {
			return null;
		}
		
		ASN1TaggedObject ref = ASN1TaggedObject.getInstance(obj);
		if (ref.getTagNo() != tagNo) {
			return null;
		}
		return ref.getObject();
	}

	public static ASN1Sequence createASN1Sequence(ASN1Encodable  ... values) {
		if (values == null) {
			return null;
		}
		ASN1EncodableVector entries = new ASN1EncodableVector();
		for (ASN1Encodable asn1Encodable : values) {
			if (asn1Encodable != null) {
				entries.add(asn1Encodable);
			}
		}
		return new DERSequence(entries);
	}

	public static ASN1Sequence createASN1Sequence(Collection<?> values) {
		if (values == null) {
			return null;
		}
		ASN1EncodableVector entries = new ASN1EncodableVector();
		for (Object asn1Encodable : values) {
			if (asn1Encodable != null) {
				entries.add((ASN1Encodable) asn1Encodable);
			}
		}
		return new DERSequence(entries);
	}
	
	public static ASN1TaggedObject tag(int tagNo, ASN1Encodable e) {
		return e == null? null: new DERTaggedObject(tagNo, e);
	}
	
	public static ASN1Integer integer(Integer e) {
		return e == null? null: new ASN1Integer(e);
	}
}
