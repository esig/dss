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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * The common parameters used for a b-level signature creation
 */
@SuppressWarnings("serial")
public class RemoteBLevelParameters implements Serializable {

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

	/** The claimed signer roles */
	private List<String> claimedSignerRoles;
	/** Signed assertions */
	private List<String> signedAssertions;

	/** Signature policy id */
	private String policyId;
	/** Qualifier attribute for XAdES Identifier */
	private ObjectIdentifierQualifier policyQualifier;
	/** The signature policy description */
	private String policyDescription;
	/** The signature policy digest algorithm */
	private DigestAlgorithm policyDigestAlgorithm;
	/** The signature policy digest value */
	private byte[] policyDigestValue;
	/** The signature policy access URI */
	private String policySpuri;

	/** Commitment type indications */
	private List<CommitmentTypeEnum> commitmentTypeIndications;

	/** SignerLocation postal address */
	private List<String> signerLocationPostalAddress = new ArrayList<>();
	/** SignerLocation postal code */
	private String signerLocationPostalCode;
	/** SignerLocation locality */
	private String signerLocationLocality;
	/** SignerLocation state or province */
	private String signerLocationStateOrProvince;
	/** SignerLocation country */
	private String signerLocationCountry;
	/** SignerLocation street */
	private String signerLocationStreet;

	/**
	 * Default constructor
	 */
	public RemoteBLevelParameters() {
		// empty
	}

	/**
	 * Gets if the trust anchor policy is used for -B and -LT levels
	 *
	 * @return indicates the trust anchor policy shall be used when creating -B and -LT levels
	 */
	public boolean isTrustAnchorBPPolicy() {
		return trustAnchorBPPolicy;
	}

	/**
	 * Allows to set the trust anchor policy to use when creating -B and -LT levels.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are
	 * included when building -B level.
	 *
	 * @param trustAnchorBPPolicy
	 *            {@code boolean}
	 */
	public void setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
	}

	/**
	 * Get the signature policy (EPES)
	 *
	 * @return the policy id
	 */
	public String getPolicyId() {
		return policyId;
	}

	/**
	 * Set the signature policy (EPES)
	 *
	 * @param id
	 *            the policy id
	 */
	public void setPolicyId(final String id) {
		this.policyId = id;
	}

	/**
	 * Get the identifier qualifier
	 *
	 * @return the qualifier
	 */
	public ObjectIdentifierQualifier getPolicyQualifier() {
		return policyQualifier;
	}

	/**
	 * Set the identifier qualifier
	 *
	 * @param qualifier
	 *            the qualifier
	 */
	public void setPolicyQualifier(ObjectIdentifierQualifier qualifier) {
		this.policyQualifier = qualifier;
	}

	/**
	 * Get the signature policy description
	 *
	 * @return the signature policy description
	 */
	public String getPolicyDescription() {
		return policyDescription;
	}

	/**
	 * Set the signature policy description
	 *
	 * @param description
	 *            the policy description
	 */
	public void setPolicyDescription(String description) {
		this.policyDescription = description;
	}

	/**
	 * Return the hash algorithm for the signature policy
	 *
	 * @return the used digest algorithm for the policy
	 */
	public DigestAlgorithm getPolicyDigestAlgorithm() {
		return policyDigestAlgorithm;
	}

	/**
	 * Set the hash algorithm for the explicit signature policy
	 *
	 * @param digestAlgorithm
	 *            the used digest algorithm for the policy
	 */
	public void setPolicyDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.policyDigestAlgorithm = digestAlgorithm;
	}

	/**
	 * Get the hash value of the explicit signature policy
	 *
	 * @return the digest value for the policy
	 */
	public byte[] getPolicyDigestValue() {
		return policyDigestValue;
	}

	/**
	 * Set the hash value of implicit signature policy
	 *
	 * @param digestValue
	 *            the digest of the policy
	 */
	public void setPolicyDigestValue(final byte[] digestValue) {
		this.policyDigestValue = digestValue;
	}

	/**
	 * Get the SP URI (signature policy URI)
	 *
	 * @return the signature policy URI
	 */
	public String getPolicySpuri() {
		return policySpuri;
	}

	/**
	 * Set the SP URI (signature policy URI)
	 *
	 * @param spuri
	 *            the signature policy URI
	 */
	public void setPolicySpuri(String spuri) {
		this.policySpuri = spuri;
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
		this.signingDate = signingDate;
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
	 * Set a list of claimed signer roles
	 * 
	 * @param claimedSignerRoles
	 *            a list of claimed signer roles
	 */
	public void setClaimedSignerRoles(List<String> claimedSignerRoles) {
		this.claimedSignerRoles = claimedSignerRoles;
	}

	/**
	 * Gets signed assertions
	 *
	 * @return the list of {@link String} signed assertions
	 */
	public List<String> getSignedAssertions() {
		return signedAssertions;
	}

	/**
	 * Sets signed assertions
	 *
	 * @param signedAssertions the list of {@link String} signed assertions
	 */
	public void setSignedAssertions(List<String> signedAssertions) {
		this.signedAssertions = signedAssertions;
	}

	/**
	 * Get the commitment type indications
	 * 
	 * @return the list of commitment type indications
	 */
	public List<CommitmentTypeEnum> getCommitmentTypeIndications() {
		return commitmentTypeIndications;
	}

	/**
	 * Set the commitment type indications {@code CommitmentTypeEnum}
	 * 
	 * @param commitmentTypeIndications
	 *            a list of commitment type indications
	 */
	public void setCommitmentTypeIndications(List<CommitmentTypeEnum> commitmentTypeIndications) {
		this.commitmentTypeIndications = commitmentTypeIndications;
	}

	/**
	 * Gets the signer location country
	 *
	 * @return {@link String}
	 */
	public String getSignerLocationCountry() {
		return signerLocationCountry;
	}

	/**
	 * Sets the signer location country
	 *
	 * @param country {@link String}
	 */
	public void setSignerLocationCountry(final String country) {
		this.signerLocationCountry = country;
	}

	/**
	 * Gets the signer location locality (city)
	 *
	 * @return {@link String}
	 */
	public String getSignerLocationLocality() {
		return signerLocationLocality;
	}

	/**
	 * Sets the signer location locality (city)
	 *
	 * @param locality {@link String}
	 */
	public void setSignerLocationLocality(final String locality) {
		this.signerLocationLocality = locality;
	}

	/**
	 * Gets the signer location postal address
	 *
	 * @return a list of postal address {@link String}s
	 */
	public List<String> getSignerLocationPostalAddress() {
		return signerLocationPostalAddress;
	}

	/**
	 * Sets the signer location postal address
	 *
	 * @param postalAddress a list of postal address {@link String}s
	 */
	public void setSignerLocationPostalAddress(final List<String> postalAddress) {
		this.signerLocationPostalAddress = postalAddress;
	}

	/**
	 * Gets the signer location postal code
	 *
	 * @return {@link String}
	 */
	public String getSignerLocationPostalCode() {
		return signerLocationPostalCode;
	}

	/**
	 * Sets the signer location postal code
	 *
	 * @param postalCode {@link String}
	 */
	public void setSignerLocationPostalCode(String postalCode) {
		this.signerLocationPostalCode = postalCode;
	}

	/**
	 * Gets the signer location state or province
	 *
	 * @return {@link String}
	 */
	public String getSignerLocationStateOrProvince() {
		return signerLocationStateOrProvince;
	}

	/**
	 * Sets the signer location state or province
	 *
	 * @param stateOrProvince {@link String}
	 */
	public void setSignerLocationStateOrProvince(String stateOrProvince) {
		this.signerLocationStateOrProvince = stateOrProvince;
	}

	/**
	 * Gets the signer location street
	 *
	 * @return {@link String}
	 */
	public String getSignerLocationStreet() {
		return signerLocationStreet;
	}

	/**
	 * Sets the signer location street
	 *
	 * @param street {@link String}
	 */
	public void setSignerLocationStreet(String street) {
		this.signerLocationStreet = street;
	}

	/**
	 * Adds an address item to the complete address.
	 *
	 * @param addressItem
	 *            an address line
	 */
	public void addSignerLocationPostalAddress(final String addressItem) {
		if (signerLocationPostalAddress == null) {
			signerLocationPostalAddress = new ArrayList<>();
		}
		signerLocationPostalAddress.add(addressItem);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((claimedSignerRoles == null) ? 0 : claimedSignerRoles.hashCode());
		result = (prime * result) + ((commitmentTypeIndications == null) ? 0 : commitmentTypeIndications.hashCode());
		result = (prime * result) + ((policyDescription == null) ? 0 : policyDescription.hashCode());
		result = (prime * result) + ((policyDigestAlgorithm == null) ? 0 : policyDigestAlgorithm.hashCode());
		result = (prime * result) + Arrays.hashCode(policyDigestValue);
		result = (prime * result) + ((policyId == null) ? 0 : policyId.hashCode());
		result = (prime * result) + ((policySpuri == null) ? 0 : policySpuri.hashCode());
		result = (prime * result) + ((signerLocationCountry == null) ? 0 : signerLocationCountry.hashCode());
		result = (prime * result) + ((signerLocationLocality == null) ? 0 : signerLocationLocality.hashCode());
		result = (prime * result) + ((signerLocationPostalAddress == null) ? 0 : signerLocationPostalAddress.hashCode());
		result = (prime * result) + ((signerLocationPostalCode == null) ? 0 : signerLocationPostalCode.hashCode());
		result = (prime * result) + ((signerLocationStateOrProvince == null) ? 0 : signerLocationStateOrProvince.hashCode());
		result = (prime * result) + ((signerLocationStreet == null) ? 0 : signerLocationStreet.hashCode());
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
		RemoteBLevelParameters other = (RemoteBLevelParameters) obj;
		if (claimedSignerRoles == null) {
			if (other.claimedSignerRoles != null) {
				return false;
			}
		} else if (!claimedSignerRoles.equals(other.claimedSignerRoles)) {
			return false;
		}
		if (commitmentTypeIndications == null) {
			if (other.commitmentTypeIndications != null) {
				return false;
			}
		} else if (!commitmentTypeIndications.equals(other.commitmentTypeIndications)) {
			return false;
		}
		if (policyDescription == null) {
			if (other.policyDescription != null) {
				return false;
			}
		} else if (!policyDescription.equals(other.policyDescription)) {
			return false;
		}
		if (policyDigestAlgorithm != other.policyDigestAlgorithm) {
			return false;
		}
		if (!Arrays.equals(policyDigestValue, other.policyDigestValue)) {
			return false;
		}
		if (policyId == null) {
			if (other.policyId != null) {
				return false;
			}
		} else if (!policyId.equals(other.policyId)) {
			return false;
		}
		if (policySpuri == null) {
			if (other.policySpuri != null) {
				return false;
			}
		} else if (!policySpuri.equals(other.policySpuri)) {
			return false;
		}
		if (signerLocationCountry == null) {
			if (other.signerLocationCountry != null) {
				return false;
			}
		} else if (!signerLocationCountry.equals(other.signerLocationCountry)) {
			return false;
		}
		if (signerLocationLocality == null) {
			if (other.signerLocationLocality != null) {
				return false;
			}
		} else if (!signerLocationLocality.equals(other.signerLocationLocality)) {
			return false;
		}
		if (signerLocationPostalAddress == null) {
			if (other.signerLocationPostalAddress != null) {
				return false;
			}
		} else if (!signerLocationPostalAddress.equals(other.signerLocationPostalAddress)) {
			return false;
		}
		if (signerLocationPostalCode == null) {
			if (other.signerLocationPostalCode != null) {
				return false;
			}
		} else if (!signerLocationPostalCode.equals(other.signerLocationPostalCode)) {
			return false;
		}
		if (signerLocationStateOrProvince == null) {
			if (other.signerLocationStateOrProvince != null) {
				return false;
			}
		} else if (!signerLocationStateOrProvince.equals(other.signerLocationStateOrProvince)) {
			return false;
		}
		if (signerLocationStreet == null) {
			if (other.signerLocationStreet != null) {
				return false;
			}
		} else if (!signerLocationStreet.equals(other.signerLocationStreet)) {
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
		return "RemoteBLevelParameters [trustAnchorBPPolicy=" + trustAnchorBPPolicy + ", signingDate=" + signingDate + ", claimedSignerRoles=" + claimedSignerRoles
				+ "Policy [id=" + policyId + ", description=" + policyDescription + ", digestAlgorithm=" + policyDigestAlgorithm + ", digestValue=" 
				+ Arrays.toString(policyDigestValue) + ", spuri=" + policySpuri + "]" + ", commitmentTypeIndication=" + commitmentTypeIndications 
				+ ", SignerLocation [postalAddress=" + signerLocationPostalAddress + ", postalCode=" + signerLocationPostalCode + ", locality=" 
				+ signerLocationLocality + ", stateOrProvince=" + signerLocationStateOrProvince + ", country=" + signerLocationCountry + ", street=" 
				+ signerLocationStreet + "]]";
	}

}