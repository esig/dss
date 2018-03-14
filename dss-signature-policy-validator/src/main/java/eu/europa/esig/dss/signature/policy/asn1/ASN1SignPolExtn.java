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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import eu.europa.esig.dss.signature.policy.SignPolExtn;

/**
 * 
 * SignPolExtn ::= SEQUENCE {
 *  extnID OBJECT IDENTIFIER,
 *  extnValue OCTET STRING } 
 * @author davyd.santos
 *
 */
public class ASN1SignPolExtn extends ASN1Object implements SignPolExtn {
	private String extnID;
	private byte[] extnValue;

	public static ASN1SignPolExtn getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SignPolExtn((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SignPolExtn(ASN1Sequence.getInstance(obj));
        }

        return null;
	}
	
	public ASN1SignPolExtn(ASN1Sequence as) {
		if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		extnID = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0)).getId();
		extnValue = ASN1OctetString.getInstance(as.getObjectAt(1)).getOctets();
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(new ASN1ObjectIdentifier(extnID), new DEROctetString(extnValue));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtn#getExtnID()
	 */
	@Override
	public String getExtnID() {
		return extnID;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolExtn#getExtnValue()
	 */
	@Override
	public byte[] getExtnValue() {
		return extnValue;
	}

}
