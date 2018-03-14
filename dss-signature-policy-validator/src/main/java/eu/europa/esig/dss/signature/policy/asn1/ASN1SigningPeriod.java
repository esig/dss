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

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.SigningPeriod;

/**
 * SigningPeriod ::= SEQUENCE {
 *  notBefore GeneralizedTime,
 *  notAfter GeneralizedTime OPTIONAL } 
 * @author davyd.santos
 *
 */
public class ASN1SigningPeriod extends ASN1Object implements SigningPeriod {
	private Date notBefore;
	private Date notAfter;

	public static ASN1SigningPeriod getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SigningPeriod((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SigningPeriod(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1SigningPeriod(ASN1Sequence as) {
		if (as.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		try {
			notBefore = ASN1GeneralizedTime.getInstance(as.getObjectAt(0)).getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException("Error parsing SigningPeriod.notBefore", e);
		}
		try {
			notAfter = ASN1GeneralizedTime.getInstance(as.getObjectAt(1)).getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException("Error parsing SigningPeriod.notAfter", e);
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(new ASN1GeneralizedTime(notBefore));
		entries.add(new ASN1GeneralizedTime(notAfter));
		return new DERSequence(entries);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SigningPeriod#getNotBefore()
	 */
	@Override
	public Date getNotBefore() {
		return notBefore;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SigningPeriod#getNotAfter()
	 */
	@Override
	public Date getNotAfter() {
		return notAfter;
	}

}
