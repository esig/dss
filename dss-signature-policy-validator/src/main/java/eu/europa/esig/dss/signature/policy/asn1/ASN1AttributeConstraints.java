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

import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.tag;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import eu.europa.esig.dss.signature.policy.AttributeConstraints;

/**
 * AttributeConstraints ::= SEQUENCE {
 *         attributeTypeConstarints        [0] AttributeTypeConstraints
 *                                                        OPTIONAL,
 *         attributeValueConstarints       [1] AttributeValueConstraints
 *                                                        OPTIONAL }
 *                                                        
 * -- source RFC 2459
 * AttributeTypeAndValue ::= SEQUENCE {
 *         type     AttributeType,
 *         value    AttributeValue }
 * 
 * AttributeType ::= OBJECT IDENTIFIER
 * 
 * AttributeValue ::= ANY DEFINED BY AttributeType
 * 
 * @author davyd.santos
 *
 */
public class ASN1AttributeConstraints extends ASN1Object implements AttributeConstraints {
	private List<String> attributeTypeConstraints;
	private List<AttributeTypeAndValue> attributeValueConstraints;
	
	public static ASN1AttributeConstraints getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1AttributeConstraints(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1AttributeConstraints(ASN1Sequence as) {
		if (as == null || as.size() == 0) {
			return;
		}
		if (as.size() > 2) {
			throw new IllegalArgumentException("Invalid size: " + as.size());
		}
		ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(as.getObjectAt(0));
		if (taggedObject != null && taggedObject.getTagNo() == 0) {
			attributeTypeConstraints = new ArrayList<String>();
			for (ASN1Encodable asn1Encodable : ASN1Sequence.getInstance(taggedObject.getObject())) {
				attributeTypeConstraints.add(ASN1ObjectIdentifier.getInstance(asn1Encodable).getId());
			}
			
			taggedObject = as.size() > 1? ASN1TaggedObject.getInstance(as.getObjectAt(1)): null;
		}
		
		if (taggedObject != null && taggedObject.getTagNo() == 1) {
			attributeValueConstraints = new ArrayList<AttributeTypeAndValue>();
			for (ASN1Encodable asn1Encodable : ASN1Sequence.getInstance(taggedObject.getObject())) {
				attributeValueConstraints.add(AttributeTypeAndValue.getInstance(asn1Encodable));
			}
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1Sequence attTypes = null;
		ASN1Sequence attTypesAndValues = null;
		
		if (attributeTypeConstraints != null) {
			ASN1Encodable[] values = new ASN1Encodable[attributeTypeConstraints.size()];
			for (int i=0;i<values.length; i++) {
				values[i] = new ASN1ObjectIdentifier(attributeTypeConstraints.get(i));
			}
			attTypes = createASN1Sequence(values);
		}
		
		if (attributeValueConstraints != null) {
			ASN1Encodable[] values = attributeValueConstraints.toArray(new ASN1Encodable[attributeValueConstraints.size()]);
			attTypesAndValues = createASN1Sequence(values);
		}
		
		return createASN1Sequence(tag(0, attTypes), tag(1, attTypesAndValues));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeConstraints#getAttributeTypeConstraints()
	 */
	@Override
	public List<String> getAttributeTypeConstraints() {
		return attributeTypeConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeConstraints#getAttributeValueConstraints()
	 */
	@Override
	public List<AttributeTypeAndValue> getAttributeValueConstraints() {
		return attributeValueConstraints;
	}
}
