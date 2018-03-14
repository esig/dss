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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.SignPolExtensions;
import eu.europa.esig.dss.signature.policy.SignPolExtn;

public class ASN1SignPolExtensions extends ASN1Object implements SignPolExtensions {
	
	private List<SignPolExtn> signPolExtn = new ArrayList<SignPolExtn>();

	public static ASN1SignPolExtensions getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1SignPolExtensions(ASN1Sequence.getInstance(obj));
        }

        return null;
	}
	
	public ASN1SignPolExtensions(ASN1Sequence as) {
		for(ASN1Encodable e : as) {
			signPolExtn.add(ASN1SignPolExtn.getInstance(e));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(signPolExtn);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtensions#getSignPolExtn()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtn;
	}

}
