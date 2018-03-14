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

import eu.europa.esig.dss.signature.policy.CommitmentRule;
import eu.europa.esig.dss.signature.policy.CommonRules;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignatureValidationPolicy;
import eu.europa.esig.dss.signature.policy.SigningPeriod;

/**
 * 
 * SignatureValidationPolicy ::= SEQUENCE {
 *  signingPeriod SigningPeriod,
 *  commonRules CommonRules,
 *  commitmentRules CommitmentRules,
 *  signPolExtensions SignPolExtensions OPTIONAL
 *  } 
 * @author davyd.santos
 *
 */
public class ASN1SignatureValidationPolicy extends ASN1Object implements SignatureValidationPolicy {
	private ASN1SigningPeriod signingPeriod;
	private ASN1CommonRules commonRules;
	private List<CommitmentRule> commitmentRules;
	private ASN1SignPolExtensions signPolExtensions;

	public static ASN1SignatureValidationPolicy getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SignatureValidationPolicy((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SignatureValidationPolicy(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1SignatureValidationPolicy(ASN1Sequence as) {
		if (!(as.size() == 3 || as.size() == 4)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		signingPeriod = ASN1SigningPeriod.getInstance(as.getObjectAt(0));
		commonRules = ASN1CommonRules.getInstance(as.getObjectAt(1));
		
		ASN1Sequence commitmentRulesSequence = ASN1Sequence.getInstance(as.getObjectAt(2));
		if (commitmentRulesSequence.size() > 0) {
			commitmentRules = new ArrayList<CommitmentRule>();
			for (ASN1Encodable commitmentRule : commitmentRulesSequence) {
				commitmentRules.add(ASN1CommitmentRule.getInstance(commitmentRule));
			}			
		}
		
		if (as.size() == 4) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(as.getObjectAt(5));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ASN1Utils.createASN1Sequence(
				signingPeriod, 
				commonRules, 
				ASN1Utils.createASN1Sequence(commitmentRules), 
				signPolExtensions);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignatureValidationPolicy#getSigningPeriod()
	 */
	@Override
	public SigningPeriod getSigningPeriod() {
		return signingPeriod;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignatureValidationPolicy#getCommonRules()
	 */
	@Override
	public CommonRules getCommonRules() {
		return commonRules;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignatureValidationPolicy#getCommitmentRules()
	 */
	@Override
	public List<CommitmentRule> getCommitmentRules() {
		return commitmentRules;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignatureValidationPolicy#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
