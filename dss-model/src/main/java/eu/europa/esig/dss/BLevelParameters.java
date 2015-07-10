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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@SuppressWarnings("serial")
@XmlAccessorType(XmlAccessType.FIELD)
public class BLevelParameters implements Serializable {

	/**
	 * This variable indicates if the Baseline profile's trust anchor policy shall be followed:
	 * ETSI TS 103 171 V2.1.1 (2012-03)
	 * 6.2.1 Placement of the signing certificate
	 * ../..
	 * it is advised to include at least the unavailable intermediary certificates up to but not including the CAs present in the TSLs,
	 * ../..
	 * This rule applies as follows: when -B level is constructed the trust anchor is not included, when -LT level is constructed the trust anchor is included.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are included when -B level is constructed.
	 */
	private boolean trustAnchorBPPolicy = true;

	@XmlJavaTypeAdapter(value = DateAdapter.class)
	private Date signingDate = new Date();

	/**
	 * The digest method used to create the digest of the signer's certificate.
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA1;

	private List<String> claimedSignerRoles;
	private List<String> certifiedSignerRoles;

	private Policy signaturePolicy;

	// TODO: move to a CAdES-B specific parameter class
	private String contentIdentifierPrefix;
	private String contentIdentifierSuffix;

	private List<String> commitmentTypeIndication;
	private SignerLocation signerLocation;
	private String contentHintsType;
	private String contentHintsDescription;

	public BLevelParameters() {
	}

	/**
	 * @return indicates the trust anchor policy shall be used when creating -B and -LT levels
	 */
	public boolean isTrustAnchorBPPolicy() {
		return trustAnchorBPPolicy;
	}

	/**
	 * Allows to set the trust anchor policy to use when creating -B and -LT levels.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are included when building -B level.
	 *
	 * @param trustAnchorBPPolicy {@code boolean}
	 */
	public void setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
	}

	/**
	 * @return the signature policy to use during the signature creation process
	 */
	public Policy getSignaturePolicy() {

		return signaturePolicy;
	}

	/**
	 * This setter allows to indicate the signature policy to use.
	 *
	 * @param signaturePolicy signature policy to use
	 */
	public void setSignaturePolicy(final Policy signaturePolicy) {

		this.signaturePolicy = signaturePolicy;
	}

	/**
	 * THIS VALUE WILL BE SET AUTOMATICALLY IF LEFT BLANK
	 *
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later. The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 *
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	/**
	 * @param contentIdentifierSuffix
	 * @see #getContentIdentifierSuffix()
	 */
	public void setContentIdentifierSuffix(String contentIdentifierSuffix) {
		this.contentIdentifierSuffix = contentIdentifierSuffix;
	}

	public String getContentHintsType() {
		return contentHintsType;
	}

	public void setContentHintsType(String contentHintsType) {
		this.contentHintsType = contentHintsType;
	}

	public String getContentHintsDescription() {
		return contentHintsDescription;
	}

	public void setContentHintsDescription(String contentHintsDescription) {
		this.contentHintsDescription = contentHintsDescription;
	}

	/**
	 * Set the signing date
	 *
	 * @param signingDate the value
	 */
	public void setSigningDate(final Date signingDate) {

		this.signingDate = signingDate;
	}

	/**
	 * Get the signing date
	 *
	 * @return the value
	 */
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * This property is a part of the standard:<br>
	 * 7.2.2 The SigningCertificate element (101 903 V1.4.2 (2010-12) XAdES)<br>
	 * The digest method indicates the digest algorithm to be used to calculate the CertDigest element that contains the
	 * digest for each certificate referenced in the sequence.
	 *
	 * @param signingCertificateDigestMethod
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm).
	 *
	 * @return
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * Get claimed role
	 *
	 * @return the value
	 */
	public List<String> getClaimedSignerRoles() {
		return claimedSignerRoles;
	}

	/**
	 * Adds a claimed signer role
	 *
	 * @param claimedSignerRole the value
	 */
	public void addClaimedSignerRole(final String claimedSignerRole) {
		if ((claimedSignerRole == null) || (claimedSignerRole.length() == 0)) {
			throw new NullPointerException("claimedSignerRole");
		}
		if (claimedSignerRoles == null) {
			claimedSignerRoles = new ArrayList<String>();
		}
		claimedSignerRoles.add(claimedSignerRole);
	}

	public List<String> getCertifiedSignerRoles() {
		return certifiedSignerRoles;
	}

	/**
	 * Adds a certified signer role
	 *
	 * @param certifiedSignerRole the value
	 */
	public void addCertifiedSignerRole(final String certifiedSignerRole) {
		throw new DSSException("eu.europa.esig.dss.BLevelParameters.addCertifiedSignerRole");
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.11.1 commitment-type-indication Attribute
	 * There may be situations where a signer wants to explicitly indicate to a verifier that by signing the data, it illustrates a
	 * type of commitment on behalf of the signer. The commitment-type-indication attribute conveys such
	 * information.
	 */
	public List<String> getCommitmentTypeIndications() {
		return commitmentTypeIndication;
	}

	public void setCommitmentTypeIndications(List<String> commitmentTypeIndication) {
		this.commitmentTypeIndication = commitmentTypeIndication;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later. The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 *
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	/**
	 * @param contentIdentifierPrefix
	 * @see #getContentIdentifierPrefix()
	 */
	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.11.2 signer-location Attribute
	 * The signer-location attribute specifies a mnemonic for an address associated with the signer at a particular
	 * geographical (e.g. city) location. The mnemonic is registered in the country in which the signer is located and is used in
	 * the provision of the Public Telegram Service (according to Recommendation ITU-T F.1 [11]).
	 * The signer-location attribute shall be a signed attribute.
	 *
	 * The following object identifier identifies the signer-location attribute:
	 * id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 17}
	 * Signer-location attribute values have ASN.1 type SignerLocation:
	 * SignerLocation ::= SEQUENCE { -- at least one of the following shall be present:
	 * countryName [0] DirectoryString OPTIONAL,
	 * -- As used to name a Country in X.500
	 * localityName [1] DirectoryString OPTIONAL,
	 * -- As used to name a locality in X.500
	 * postalAdddress [2] PostalAddress OPTIONAL }
	 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
	 *
	 * @return the location
	 */
	public SignerLocation getSignerLocation() {
		return signerLocation;
	}

	/**
	 * @param signerLocation the location to set
	 */
	public void setSignerLocation(final SignerLocation signerLocation) {
		this.signerLocation = signerLocation;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((certifiedSignerRoles == null) ? 0 : certifiedSignerRoles.hashCode());
		result = (prime * result) + ((claimedSignerRoles == null) ? 0 : claimedSignerRoles.hashCode());
		result = (prime * result) + ((commitmentTypeIndication == null) ? 0 : commitmentTypeIndication.hashCode());
		result = (prime * result) + ((contentHintsDescription == null) ? 0 : contentHintsDescription.hashCode());
		result = (prime * result) + ((contentHintsType == null) ? 0 : contentHintsType.hashCode());
		result = (prime * result) + ((contentIdentifierPrefix == null) ? 0 : contentIdentifierPrefix.hashCode());
		result = (prime * result) + ((contentIdentifierSuffix == null) ? 0 : contentIdentifierSuffix.hashCode());
		result = (prime * result) + ((signaturePolicy == null) ? 0 : signaturePolicy.hashCode());
		result = (prime * result) + ((signerLocation == null) ? 0 : signerLocation.hashCode());
		result = (prime * result) + ((signingCertificateDigestMethod == null) ? 0 : signingCertificateDigestMethod.hashCode());
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
		if (certifiedSignerRoles == null) {
			if (other.certifiedSignerRoles != null) {
				return false;
			}
		} else if (!certifiedSignerRoles.equals(other.certifiedSignerRoles)) {
			return false;
		}
		if (claimedSignerRoles == null) {
			if (other.claimedSignerRoles != null) {
				return false;
			}
		} else if (!claimedSignerRoles.equals(other.claimedSignerRoles)) {
			return false;
		}
		if (commitmentTypeIndication == null) {
			if (other.commitmentTypeIndication != null) {
				return false;
			}
		} else if (!commitmentTypeIndication.equals(other.commitmentTypeIndication)) {
			return false;
		}
		if (contentHintsDescription == null) {
			if (other.contentHintsDescription != null) {
				return false;
			}
		} else if (!contentHintsDescription.equals(other.contentHintsDescription)) {
			return false;
		}
		if (contentHintsType == null) {
			if (other.contentHintsType != null) {
				return false;
			}
		} else if (!contentHintsType.equals(other.contentHintsType)) {
			return false;
		}
		if (contentIdentifierPrefix == null) {
			if (other.contentIdentifierPrefix != null) {
				return false;
			}
		} else if (!contentIdentifierPrefix.equals(other.contentIdentifierPrefix)) {
			return false;
		}
		if (contentIdentifierSuffix == null) {
			if (other.contentIdentifierSuffix != null) {
				return false;
			}
		} else if (!contentIdentifierSuffix.equals(other.contentIdentifierSuffix)) {
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
		if (signingCertificateDigestMethod != other.signingCertificateDigestMethod) {
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
		return "BLevelParameters [trustAnchorBPPolicy=" + trustAnchorBPPolicy + ", signingDate=" + signingDate + ", signingCertificateDigestMethod="
				+ signingCertificateDigestMethod + ", claimedSignerRoles=" + claimedSignerRoles + ", certifiedSignerRoles=" + certifiedSignerRoles + ", signaturePolicy="
				+ signaturePolicy + ", contentIdentifierPrefix=" + contentIdentifierPrefix + ", contentIdentifierSuffix=" + contentIdentifierSuffix + ", commitmentTypeIndication="
				+ commitmentTypeIndication + ", signerLocation=" + signerLocation + ", contentHintsType=" + contentHintsType + ", contentHintsDescription="
				+ contentHintsDescription + "]";
	}

}
