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
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.EnuRevReq;
import eu.europa.esig.dss.signature.policy.RevReq;
import eu.europa.esig.dss.signature.policy.SignPolExtn;

/**
 * RevReq ::= SEQUENCE  {
 *     enuRevReq  EnuRevReq,
 *     exRevReq    SignPolExtensions OPTIONAL}
 * @author davyd.santos
 *
 */
public class ASN1RevReq extends ASN1Object implements RevReq {
	
	private EnuRevReq enuRevReq;
	private ASN1SignPolExtensions exRevReq;

	public static ASN1RevReq getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1RevReq(ASN1Sequence.getInstance(obj));
        }
		return null;
	}
	
	public ASN1RevReq(ASN1Sequence as) {
		if (!(as.size() == 1 || as.size() == 2)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		
		enuRevReq = ASN1EnuRevReqHelper.getInstance(as.getObjectAt(0));
		if (as.size() > 1) {
			exRevReq = ASN1SignPolExtensions.getInstance(as.getObjectAt(1));
		}
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(
				new ASN1Enumerated(enuRevReq.ordinal()),
				exRevReq);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.RevReq#getEnuRevReq()
	 */
	@Override
	public EnuRevReq getEnuRevReq() {
		return enuRevReq;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.RevReq#getExRevReq()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return exRevReq == null? null: exRevReq.getSignPolExtensions();
	}

}
