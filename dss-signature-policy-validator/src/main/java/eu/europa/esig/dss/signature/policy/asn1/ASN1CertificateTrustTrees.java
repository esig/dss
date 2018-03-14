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
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.signature.policy.CertificateTrustTrees;

/**
 * CertificateTrustTrees ::=   SEQUENCE OF CertificateTrustPoint
 * @author davyd.santos
 *
 */
public class ASN1CertificateTrustTrees extends ASN1Object implements CertificateTrustTrees {
	private List<CertificateTrustPoint> certificateTrustPoints = new ArrayList<CertificateTrustPoint>();

	public static ASN1CertificateTrustTrees getInstance(ASN1Encodable obj) {
		if (obj != null) {
			return new ASN1CertificateTrustTrees(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public ASN1CertificateTrustTrees(ASN1Sequence as) {
		for (ASN1Encodable asn1Encodable : as) {
			certificateTrustPoints.add(ASN1CertificateTrustPoint.getInstance(asn1Encodable));
		}
	}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERSequence(certificateTrustPoints.toArray(new ASN1CertificateTrustPoint[certificateTrustPoints.size()]));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustTrees#getCertificateTrustPoints()
	 */
	@Override
	public List<CertificateTrustPoint> getCertificateTrustPoints() {
		return certificateTrustPoints;
	}

}
