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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import eu.europa.esig.dss.signature.policy.AttributeConstraints;
import eu.europa.esig.dss.signature.policy.AttributeTrustCondition;
import eu.europa.esig.dss.signature.policy.CertRevReq;
import eu.europa.esig.dss.signature.policy.CertificateTrustTrees;
import eu.europa.esig.dss.signature.policy.HowCertAttribute;

/**
 * AttributeTrustCondition ::= SEQUENCE {
 *       attributeMandated            BOOLEAN,
 *                                    -- Attribute must be present
 *       howCertAttribute             HowCertAttribute,
 *       attrCertificateTrustTrees   [0] CertificateTrustTrees  OPTIONAL,
 *       attrRevReq                  [1] CertRevReq             OPTIONAL,
 *       attributeConstraints        [2] AttributeConstraints   OPTIONAL }
 * @author davyd.santos
 *
 */
public class ASN1AttributeTrustCondition extends ASN1Object implements AttributeTrustCondition {
	private boolean attributeMandated;
	private HowCertAttribute howCertAttribute;
	private ASN1CertificateTrustTrees attrCertificateTrustTrees;
	private ASN1CertRevReq attrRevReq;
	private ASN1AttributeConstraints attributeConstraints;
	
	public static ASN1AttributeTrustCondition getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1AttributeTrustCondition(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1AttributeTrustCondition(ASN1Sequence as) {
		int index = 0;
		attributeMandated = ASN1Boolean.getInstance(as.getObjectAt(index++)).isTrue();
		howCertAttribute = ASN1HowCertAttributeHelper.getInstance(as.getObjectAt(index++));
		
		ASN1TaggedObject tagged = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		
		if (tagged != null && tagged.getTagNo() == 0) {
			attrCertificateTrustTrees = ASN1CertificateTrustTrees.getInstance(tagged.getObject());
			
			tagged = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (tagged != null && tagged.getTagNo() == 1) {
			attrRevReq = ASN1CertRevReq.getInstance(tagged.getObject());
			
			tagged = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (tagged != null && tagged.getTagNo() == 2) {
			attributeConstraints = ASN1AttributeConstraints.getInstance(tagged.getObject());
			
			index++;
		}
		if (as.size() > index) {
			throw new IllegalArgumentException("Invalid sequence size: " + as.size());
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				ASN1Boolean.getInstance(attributeMandated),
				new ASN1Enumerated(howCertAttribute.ordinal()),
				tag(0, attrCertificateTrustTrees),
				tag(1, attrRevReq),
				tag(2, attributeConstraints));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeTrustCondition#isAttributeMandated()
	 */
	@Override
	public boolean isAttributeMandated() {
		return attributeMandated;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeTrustCondition#getHowCertAttribute()
	 */
	@Override
	public HowCertAttribute getHowCertAttribute() {
		return howCertAttribute;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeTrustCondition#getAttrCertificateTrustTrees()
	 */
	@Override
	public CertificateTrustTrees getAttrCertificateTrustTrees() {
		return attrCertificateTrustTrees;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeTrustCondition#getAttrRevReq()
	 */
	@Override
	public CertRevReq getAttrRevReq() {
		return attrRevReq;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AttributeTrustCondition#getAttributeConstraints()
	 */
	@Override
	public AttributeConstraints getAttributeConstraints() {
		return attributeConstraints;
	}

}
