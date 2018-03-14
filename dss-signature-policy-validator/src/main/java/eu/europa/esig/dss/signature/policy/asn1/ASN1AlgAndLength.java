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
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.integer;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.AlgAndLength;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
/**
 * AlgAndLength ::= SEQUENCE {
 *         algID                   OBJECT IDENTIFIER,
 *         minKeyLength    INTEGER         OPTIONAL,
 *                              -- Minimum key length in bits other
 *                 SignPolExtensions OPTIONAL
 *                  }
 * @author davyd.santos
 *
 */
public class ASN1AlgAndLength extends ASN1Object implements AlgAndLength {
	private String algID;
	private Integer minKeyLength;
	private ASN1SignPolExtensions signPolExtensions;
	
	public static ASN1AlgAndLength getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1AlgAndLength(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1AlgAndLength(ASN1Sequence as) {
		algID = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0)).getId();
		if (as.size() == 1) {
			return;
		}
		ASN1Encodable asn = as.getObjectAt(1);
		if (asn instanceof ASN1Integer) {
			minKeyLength = ASN1Integer.getInstance(asn).getValue().intValue();
			
			if (as.size() == 2) {
				return;
			}
			asn = as.getObjectAt(2);
		}
		signPolExtensions = ASN1SignPolExtensions.getInstance(asn);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(new ASN1ObjectIdentifier(algID), integer(minKeyLength), signPolExtensions);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgAndLength#getAlgID()
	 */
	@Override
	public String getAlgID() {
		return algID;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgAndLength#getMinKeyLength()
	 */
	@Override
	public Integer getMinKeyLength() {
		return minKeyLength;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgAndLength#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
