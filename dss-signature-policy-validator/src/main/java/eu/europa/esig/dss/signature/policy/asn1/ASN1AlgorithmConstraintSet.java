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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import eu.europa.esig.dss.signature.policy.AlgAndLength;
import eu.europa.esig.dss.signature.policy.AlgorithmConstraintSet;

/**
 * AlgorithmConstraintSet ::= SEQUENCE {   -- Algorithm constrains on:
 * signerAlgorithmConstraints      [0]     AlgorithmConstraints OPTIONAL,
 *                                  -- signer
 * eeCertAlgorithmConstraints      [1]     AlgorithmConstraints OPTIONAL,
 *                                  -- issuer of end entity certs.
 * caCertAlgorithmConstraints      [2]     AlgorithmConstraints OPTIONAL,
 *                                  -- issuer of CA certificates
 * aaCertAlgorithmConstraints      [3]     AlgorithmConstraints OPTIONAL,
 *                                  -- Attribute Authority
 * tsaCertAlgorithmConstraints     [4]     AlgorithmConstraints OPTIONAL
 *                                  -- Time-Stamping Authority
 *                                                     }
 * @author davyd.santos
 *
 */
public class ASN1AlgorithmConstraintSet extends ASN1Object implements AlgorithmConstraintSet {
	private List<AlgAndLength> signerAlgorithmConstraints;
	private List<AlgAndLength> eeCertAlgorithmConstraints;
	private List<AlgAndLength> caCertAlgorithmConstraints;
	private List<AlgAndLength> aaCertAlgorithmConstraints;
	private List<AlgAndLength> tsaCertAlgorithmConstraints;
	
	public static ASN1AlgorithmConstraintSet getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1AlgorithmConstraintSet(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1AlgorithmConstraintSet(ASN1Sequence as) {
		int index = 0;
		ASN1TaggedObject taggedObject = as.size()>index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		if (taggedObject != null && taggedObject.getTagNo() == 0) {
			signerAlgorithmConstraints = readAlgorithmConstraints(taggedObject);
			taggedObject = as.size()>index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (taggedObject != null && taggedObject.getTagNo() == 1) {
			eeCertAlgorithmConstraints = readAlgorithmConstraints(taggedObject);
			taggedObject = as.size()>index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (taggedObject != null && taggedObject.getTagNo() == 2) {
			caCertAlgorithmConstraints = readAlgorithmConstraints(taggedObject);
			taggedObject = as.size()>index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (taggedObject != null && taggedObject.getTagNo() == 3) {
			aaCertAlgorithmConstraints = readAlgorithmConstraints(taggedObject);
			taggedObject = as.size()>index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (taggedObject != null && taggedObject.getTagNo() == 4) {
			tsaCertAlgorithmConstraints = readAlgorithmConstraints(taggedObject);
		}
		if (as.size()>index) {
			throw new IllegalArgumentException("Invalid sequence size: " + as.size());
		}
	}
	
	private List<AlgAndLength> readAlgorithmConstraints(ASN1TaggedObject taggedObj) {
		ASN1Sequence as = ASN1Sequence.getInstance(taggedObj.getObject());
		List<AlgAndLength> constraints = new ArrayList<AlgAndLength>();
		for (ASN1Encodable asn1Encodable : as) {
			constraints.add(ASN1AlgAndLength.getInstance(asn1Encodable));
		}
		return constraints;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				tag(0, createASN1Sequence(signerAlgorithmConstraints)),
				tag(1, createASN1Sequence(eeCertAlgorithmConstraints)),
				tag(2, createASN1Sequence(caCertAlgorithmConstraints)),
				tag(3, createASN1Sequence(aaCertAlgorithmConstraints)),
				tag(4, createASN1Sequence(tsaCertAlgorithmConstraints)));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgorithmConstraintSet#getSignerAlgorithmConstraints()
	 */
	@Override
	public List<AlgAndLength> getSignerAlgorithmConstraints() {
		return signerAlgorithmConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgorithmConstraintSet#getEeCertAlgorithmConstraints()
	 */
	@Override
	public List<AlgAndLength> getEeCertAlgorithmConstraints() {
		return eeCertAlgorithmConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgorithmConstraintSet#getCaCertAlgorithmConstraints()
	 */
	@Override
	public List<AlgAndLength> getCaCertAlgorithmConstraints() {
		return caCertAlgorithmConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgorithmConstraintSet#getAaCertAlgorithmConstraints()
	 */
	@Override
	public List<AlgAndLength> getAaCertAlgorithmConstraints() {
		return aaCertAlgorithmConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.AlgorithmConstraintSet#getTsaCertAlgorithmConstraints()
	 */
	@Override
	public List<AlgAndLength> getTsaCertAlgorithmConstraints() {
		return tsaCertAlgorithmConstraints;
	}

}
