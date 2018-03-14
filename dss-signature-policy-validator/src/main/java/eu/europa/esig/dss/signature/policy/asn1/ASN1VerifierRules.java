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

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.VerifierRules;

/**
 * VerifierRules ::= SEQUENCE {
 * 	 mandatedUnsignedAttr MandatedUnsignedAttr,
 * 	 signPolExtensions SignPolExtensions OPTIONAL
 * 	 }
 */ 
public class ASN1VerifierRules extends ASN1Object implements VerifierRules {
	private ASN1CMSAttrs mandatedUnsignedAttr;
	private ASN1SignPolExtensions signPolExtensions;

	public static ASN1VerifierRules getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1VerifierRules(ASN1Sequence.getInstance(obj));
        }
		return null;
	}

	public ASN1VerifierRules(ASN1Sequence as) {
		int index = 0;
		if (!(as.size() == 1 || as.size() == 2)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		mandatedUnsignedAttr = ASN1CMSAttrs.getInstance(as.getObjectAt(index++));
		if (as.size() > 1) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(as.getObjectAt(index++));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(mandatedUnsignedAttr);
		if (signPolExtensions != null) {
			entries.add(signPolExtensions);			
		}
		return new DERSequence(entries);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.VerifierRules#getMandatedUnsignedAttr()
	 */
	@Override
	public List<String> getMandatedUnsignedAttr() {
		return mandatedUnsignedAttr.getOids();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.VerifierRules#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
