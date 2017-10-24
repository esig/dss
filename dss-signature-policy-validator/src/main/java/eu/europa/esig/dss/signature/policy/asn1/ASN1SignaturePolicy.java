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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import eu.europa.esig.dss.signature.policy.SignPolicyInfo;
import eu.europa.esig.dss.signature.policy.SignaturePolicy;
/**
 * 
 * SignaturePolicy ::= SEQUENCE {
 *  signPolicyHashAlg AlgorithmIdentifier,
 *  signPolicyInfo SignPolicyInfo,
 *  signPolicyHash SignPolicyHash OPTIONAL } 
 * @author davyd.santos
 *
 */
public class ASN1SignaturePolicy extends ASN1Object implements SignaturePolicy {
	private AlgorithmIdentifier signPolicyHashAlg;
	private ASN1SignPolicyInfo signPolicyInfo;
	private byte[] signPolicyHash;
	
	public static ASN1SignaturePolicy getInstance(ASN1Object obj) {
		if (obj != null) {
            return new ASN1SignaturePolicy(ASN1Sequence.getInstance(obj));
        }

        return null;
	}

	public ASN1SignaturePolicy(ASN1Sequence as) {
        if (!(as.size() == 2 || as.size() == 3)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
        }
        signPolicyHashAlg = AlgorithmIdentifier.getInstance(as.getObjectAt(0));
        signPolicyInfo = ASN1SignPolicyInfo.getInstance(as.getObjectAt(1));
        if (as.size() == 3) {
        	signPolicyHash = DEROctetString.getInstance(as.getObjectAt(2)).getOctets();
        }
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(signPolicyHashAlg);
		entries.add(signPolicyInfo);
		if (signPolicyHash != null) {
			entries.add(new DEROctetString(signPolicyHash));			
		}
		return new DERSequence(entries);
	}
	
	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyHashAlg()
	 */
	@Override
	public AlgorithmIdentifier getSignPolicyHashAlg() {
		return signPolicyHashAlg;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyInfo()
	 */
	@Override
	public SignPolicyInfo getSignPolicyInfo() {
		return signPolicyInfo;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignaturePolicy#getSignPolicyHash()
	 */
	@Override
	public byte[] getSignPolicyHash() {
		return signPolicyHash;
	}
}
