package eu.europa.esig.dss.ws.signature.dto.parameters;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

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

	private Date signingDate = new Date();

	private List<String> claimedSignerRoles;

	/* Policy */
	private String policyId;
	/* Qualifier attribute for XAdES Identifier */
	private String policyQualifier;
	private String policyDescription;
	private DigestAlgorithm policyDigestAlgorithm;
	private byte[] policyDigestValue;
	private String policySpuri;

	private List<String> commitmentTypeIndications;

	/* SignerLocation */
	private List<String> signerLocationPostalAddress = new ArrayList<String>();
	private String signerLocationPostalCode;
	private String signerLocationLocality;
	private String signerLocationStateOrProvince;
	private String signerLocationCountry;
	private String signerLocationStreet;

	public RemoteBLevelParameters() {
	}

	/**
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
	public String getPolicyQualifier() {
		return policyQualifier;
	}

	/**
	 * Set the identifier qualifier
	 *
	 * @param qualifier
	 *            the qualifier
	 */
	public void setPolicyQualifier(String qualifier) {
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
	 * Get the commitment type indications
	 * 
	 * @return the list of commitment type indications
	 */
	public List<String> getCommitmentTypeIndications() {
		return commitmentTypeIndications;
	}

	/**
	 * Set the commitment type indications (predefined values are available in {@code CommitmentType})
	 * 
	 * @param commitmentTypeIndications
	 *            a list of commitment type indications
	 */
	public void setCommitmentTypeIndications(List<String> commitmentTypeIndications) {
		this.commitmentTypeIndications = commitmentTypeIndications;
	}


	public String getSignerLocationCountry() {
		return signerLocationCountry;
	}

	public void setSignerLocationCountry(final String country) {
		this.signerLocationCountry = country;
	}

	public String getSignerLocationLocality() {
		return signerLocationLocality;
	}

	public void setSignerLocationLocality(final String locality) {
		this.signerLocationLocality = locality;
	}

	public List<String> getSignerLocationPostalAddress() {
		return signerLocationPostalAddress;
	}

	public void setSignerLocationPostalAddress(final List<String> postalAddress) {
		this.signerLocationPostalAddress = postalAddress;
	}

	public String getSignerLocationPostalCode() {
		return signerLocationPostalCode;
	}

	public void setSignerLocationPostalCode(String postalCode) {
		this.signerLocationPostalCode = postalCode;
	}

	public String getSignerLocationStateOrProvince() {
		return signerLocationStateOrProvince;
	}

	public void setSignerLocationStateOrProvince(String stateOrProvince) {
		this.signerLocationStateOrProvince = stateOrProvince;
	}

	public String getSignerLocationStreet() {
		return signerLocationStreet;
	}

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
			signerLocationPostalAddress = new ArrayList<String>();
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