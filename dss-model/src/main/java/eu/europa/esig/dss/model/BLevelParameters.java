/**
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
 */
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.CommitmentType;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to define common b-level parameters for a signature creation
 *
 */
@SuppressWarnings("serial")
public class BLevelParameters implements Serializable {

	/**
	 * This variable indicates if the Baseline profile's trust anchor policy shall be followed:
	 * ETSI TS 103 171 V2.1.1 (2012-03)
	 * 6.2.1 Placement of the signing certificate
	 * ../..
	 * it is advised to include at least the unavailable intermediary certificates up to but not including the CAs
	 * present in the TSLs,
	 * ../..
	 * This rule applies as follows: when -B level is constructed the trust anchor is not included, when -LT level is
	 * constructed the trust anchor is included.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are
	 * included when -B level is constructed.
	 */
	private boolean trustAnchorBPPolicy = true;

	/** The claimed signing time */
	private Date signingDate = new Date();

	/** Claimed signer roles */
	private List<String> claimedSignerRoles;

	/** Signed assertions */
	private List<String> signedAssertions;

	/** The Signature Policy Identifier */
	private Policy signaturePolicy;

	/** List of commitment type indications */
	private List<CommitmentType> commitmentTypeIndications;

	/** The SignerLocation */
	private SignerLocation signerLocation;

	/**
	 * Default constructor instantiating object with default values
	 */
	public BLevelParameters() {
	}

	/**
	 * Check if the trust anchor policy shall be used when creating -B and -LT levels
	 *
	 * @return TRUE if the trust anchor policy shall be used when creating -B and -LT levels, FALSE otherwise
	 */
	public boolean isTrustAnchorBPPolicy() {
		return trustAnchorBPPolicy;
	}

	/**
	 * Allows to set the trust anchor policy to use when creating -B and -LT levels.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are
	 * included when building -B level.
	 *
	 * @param trustAnchorBPPolicy {@code boolean}
	 */
	public void setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
	}

	/**
	 * Get the signature policy
	 * 
	 * @return the signature policy to use during the signature creation process
	 */
	public Policy getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * This setter allows to indicate the signature policy to use.
	 *
	 * @param signaturePolicy
	 *            signature policy to use
	 */
	public void setSignaturePolicy(final Policy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}

	/**
	 * Get the signing date
	 *
	 * @return the signing date
	 */
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * Set the signing date
	 *
	 * @param signingDate
	 *            the signing date
	 */
	public void setSigningDate(final Date signingDate) {
		Objects.requireNonNull(signingDate, "SigningDate cannot be null!");
		this.signingDate = signingDate;
	}

	/**
	 * Set a list of claimed signer roles
	 * 
	 * @param claimedSignerRoles
	 *            a list of claimed signer roles
	 */
	public void setClaimedSignerRoles(List<String> claimedSignerRoles) {
		this.claimedSignerRoles = claimedSignerRoles;
	}

	/**
	 * Get claimed roles
	 *
	 * @return the list of claimed roles
	 */
	public List<String> getClaimedSignerRoles() {
		return claimedSignerRoles;
	}

	/**
	 * Get the signed assertions
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getSignedAssertions() {
        return signedAssertions;
    }

	/**
	 * Set signed assertions
	 *
	 * @param signedAssertions a list of {@link String}s
	 */
	public void setSignedAssertions(List<String> signedAssertions) {
        this.signedAssertions = signedAssertions;
    }

	/**
	 * Get the commitment type indications
	 * 
	 * @return the list of commitment type indications
	 */
	public List<CommitmentType> getCommitmentTypeIndications() {
		return commitmentTypeIndications;
	}

	/**
	 * Set the commitment type indications (predefined values are available in {@code CommitmentType})
	 * 
	 * @param commitmentTypeIndications
	 *            a list of commitment type indications
	 */
	public void setCommitmentTypeIndications(List<CommitmentType> commitmentTypeIndications) {
		this.commitmentTypeIndications = commitmentTypeIndications;
	}

	/**
	 * Get the signer location
	 *
	 * @return the location
	 */
	public SignerLocation getSignerLocation() {
		return signerLocation;
	}

	/**
	 * Set the signer location
	 * 
	 * @param signerLocation
	 *            the location to set
	 */
	public void setSignerLocation(final SignerLocation signerLocation) {
		this.signerLocation = signerLocation;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((claimedSignerRoles == null) ? 0 : claimedSignerRoles.hashCode());
		result = (prime * result) + ((signedAssertions == null) ? 0 : signedAssertions.hashCode());
		result = (prime * result) + ((commitmentTypeIndications == null) ? 0 : commitmentTypeIndications.hashCode());
		result = (prime * result) + ((signaturePolicy == null) ? 0 : signaturePolicy.hashCode());
		result = (prime * result) + ((signerLocation == null) ? 0 : signerLocation.hashCode());
		result = (prime * result) + ((signingDate == null) ? 0 : signingDate.hashCode());
		result = (prime * result) + (trustAnchorBPPolicy ? 1231 : 1237);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		BLevelParameters other = (BLevelParameters) obj;
		if (claimedSignerRoles == null) {
			if (other.claimedSignerRoles != null) {
				return false;
			}
		} else if (!claimedSignerRoles.equals(other.claimedSignerRoles)) {
			return false;
		}
		if (signedAssertions == null) {
			if (other.signedAssertions != null) {
				return false;
			}
		} else if (!signedAssertions.equals(other.signedAssertions)) {
			return false;
		}
		if (commitmentTypeIndications == null) {
			if (other.commitmentTypeIndications != null) {
				return false;
			}
		} else if (!commitmentTypeIndications.equals(other.commitmentTypeIndications)) {
			return false;
		}
		if (signaturePolicy == null) {
			if (other.signaturePolicy != null) {
				return false;
			}
		} else if (!signaturePolicy.equals(other.signaturePolicy)) {
			return false;
		}
		if (signerLocation == null) {
			if (other.signerLocation != null) {
				return false;
			}
		} else if (!signerLocation.equals(other.signerLocation)) {
			return false;
		}
		if (signingDate == null) {
			if (other.signingDate != null) {
				return false;
			}
		} else if (!signingDate.equals(other.signingDate)) {
			return false;
		}
		if (trustAnchorBPPolicy != other.trustAnchorBPPolicy) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "BLevelParameters [trustAnchorBPPolicy=" + trustAnchorBPPolicy + ", signingDate=" + signingDate + ", claimedSignerRoles=" + claimedSignerRoles
				+ ", signedAssertions=" + signedAssertions + ", signaturePolicy=" + signaturePolicy + ", commitmentTypeIndication=" + commitmentTypeIndications + ", signerLocation=" + signerLocation
				+ "]";
	}

}
