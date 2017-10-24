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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;

import eu.europa.esig.dss.signature.policy.AlgorithmConstraintSet;
import eu.europa.esig.dss.signature.policy.AttributeTrustCondition;
import eu.europa.esig.dss.signature.policy.CommitmentRule;
import eu.europa.esig.dss.signature.policy.CommitmentType;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.esig.dss.signature.policy.SigningCertTrustCondition;
import eu.europa.esig.dss.signature.policy.TimestampTrustCondition;

/**
 * CommitmentRule ::= SEQUENCE {
 *   selCommitmentTypes SelectedCommitmentTypes,
 *   signerAndVeriferRules [0] SignerAndVerifierRules OPTIONAL,
 *   signingCertTrustCondition [1] SigningCertTrustCondition OPTIONAL,
 *   timeStampTrustCondition [2] TimestampTrustCondition OPTIONAL,
 *   attributeTrustCondition [3] AttributeTrustCondition OPTIONAL,
 *   algorithmConstraintSet [4] AlgorithmConstraintSet OPTIONAL,
 *   signPolExtensions [5] SignPolExtensions OPTIONAL
 * }
 */
public class ASN1CommitmentRule extends ASN1Object implements CommitmentRule {

	private List<CommitmentType> selCommitmentTypes = new ArrayList<CommitmentType>();
	private ASN1SignerAndVeriferRules signerAndVeriferRules;
	private ASN1SigningCertTrustCondition signingCertTrustCondition;
	private ASN1TimestampTrustCondition timeStampTrustCondition;
	private ASN1AttributeTrustCondition attributeTrustCondition;
	private ASN1AlgorithmConstraintSet algorithmConstraintSet;
	private ASN1SignPolExtensions signPolExtensions;
	
	public static ASN1CommitmentRule getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1CommitmentRule(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}
	
	public ASN1CommitmentRule(ASN1Sequence as) {
		ASN1Sequence cts = ASN1Sequence.getInstance(as.getObjectAt(0));
		for (ASN1Encodable ct : cts) {
			this.selCommitmentTypes.add(DERNull.INSTANCE == ct? null: ASN1CommitmentType.getInstance(ct)); 
		}
		int index = 1;
		ASN1TaggedObject asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 0) {
			signerAndVeriferRules = ASN1SignerAndVeriferRules.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 1) {
			signingCertTrustCondition = ASN1SigningCertTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 2) {
			timeStampTrustCondition = ASN1TimestampTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 3) {
			attributeTrustCondition = ASN1AttributeTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 4) {
			algorithmConstraintSet = ASN1AlgorithmConstraintSet.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 5) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(asn1TaggedObject.getObject());
			
			index++;
		}
		if (as.size() > index) {
			throw new IllegalArgumentException("Unkown content found");
		}
	}
	
	protected ASN1CommitmentRule() {}
	
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		for (Object obj : selCommitmentTypes) {
			entries.add(obj == null? DERNull.INSTANCE: (ASN1Encodable) obj);
		}
		
		return createASN1Sequence(
				new DERSequence(entries),
				tag(0, signerAndVeriferRules),
				tag(1, signingCertTrustCondition),
				tag(2, timeStampTrustCondition),
				tag(3, attributeTrustCondition),
				tag(4, algorithmConstraintSet),
				tag(5, signPolExtensions));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getSelCommitmentTypes()
	 */
	@Override
	public List<CommitmentType> getSelCommitmentTypes() {
		return selCommitmentTypes;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getSignerAndVeriferRules()
	 */
	@Override
	public SignerAndVerifierRules getSignerAndVeriferRules() {
		return signerAndVeriferRules;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getSigningCertTrustCondition()
	 */
	@Override
	public SigningCertTrustCondition getSigningCertTrustCondition() {
		return signingCertTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getTimeStampTrustCondition()
	 */
	@Override
	public TimestampTrustCondition getTimeStampTrustCondition() {
		return timeStampTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getAttributeTrustCondition()
	 */
	@Override
	public AttributeTrustCondition getAttributeTrustCondition() {
		return attributeTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getAlgorithmConstraintSet()
	 */
	@Override
	public AlgorithmConstraintSet getAlgorithmConstraintSet() {
		return algorithmConstraintSet;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentRule#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
