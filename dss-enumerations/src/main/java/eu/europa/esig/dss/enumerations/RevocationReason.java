/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

/**
 * This enum is used to get String value of CRLReason
 * 
 * The CRLReason enumeration.
 * 
 * <pre>
 * CRLReason ::= ENUMERATED {
 *  unspecified             (0),
 *  keyCompromise           (1),
 *  cACompromise            (2),
 *  affiliationChanged      (3),
 *  superseded              (4),
 *  cessationOfOperation    (5),
 *  certificateHold         (6),
 *  removeFromCRL           (8),
 *  privilegeWithdrawn      (9),
 *  aACompromise           (10)
 * }
 * </pre>
 */
public enum RevocationReason implements UriBasedEnum {

	/** unspecified */
	UNSPECIFIED("unspecified", "urn:etsi:019102:revocationReason:unspecified", 0),

	/** keyCompromise */
	KEY_COMPROMISE("keyCompromise", "urn:etsi:019102:revocationReason:keyCompromise", 1),

	/** cACompromise */
	CA_COMPROMISE("cACompromise", "urn:etsi:019102:revocationReason:cACompromise", 2),

	/** affiliationChanged */
	AFFILIATION_CHANGED("affiliationChanged", "urn:etsi:019102:revocationReason:affiliationChanged", 3),

	/** superseded */
	SUPERSEDED("superseded", "urn:etsi:019102:revocationReason:superseded", 4),

	/** cessationOfOperation */
	CESSATION_OF_OPERATION("cessationOfOperation", "urn:etsi:019102:revocationReason:cessationOfOperation", 5),

	/** certificateHold */
	CERTIFICATE_HOLD("certificateHold", "urn:etsi:019102:revocationReason:certificateHold", 6),

	// Missing in ETSI VR standard
	/** removeFromCRL */
	REMOVE_FROM_CRL("removeFromCRL", "urn:etsi:019102:revocationReason:removeFromCRL", 8),

	/** privilegeWithdrawn */
	PRIVILEGE_WITHDRAWN("privilegeWithdrawn", "urn:etsi:019102:revocationReason:privilegeWithdrawn", 9),

	// Missing in ETSI VI standard
	/** aACompromise */
	AA_COMPROMISE("aACompromise", "urn:etsi:019102:revocationReason:aACompromise", 10);

	/** A name of the revocation reason */
	private final String shortName;

	/** URI in VR standard */
	private final String uri;

	/** Value of the reason */
	private final int value;

	/**
	 * Default constructor
	 *
	 * @param shortName {@link String} name
	 * @param uri {@link String} within VR
	 * @param value value of the reason
	 */
	RevocationReason(String shortName, String uri, int value) {
		this.shortName = shortName;
		this.uri = uri;
		this.value = value;
	}

	/**
	 * Returns the name of the RevocationReason
	 *
	 * @return {@link String}
	 */
	public String getShortName() {
		return shortName;
	}

	@Override
	public String getUri() {
		return uri;
	}

	/**
	 * Returns the value of the RevocationReason
	 *
	 * @return int value
	 */
	public int getValue() {
		return value;
	}

	/**
	 * Returns a {@code RevocationReason} based on the given integer value
	 *
	 * @param value to check
	 * @return {@link RevocationReason}
	 */
	public static RevocationReason fromInt(final int value) {
		for (RevocationReason reason : RevocationReason.values()) {
			if (reason.value == value) {
				return reason;
			}
		}
		return null;
	}

	/**
	 * Returns a {@code RevocationReason} based on the given label String value
	 *
	 * @param value {@link String} to check
	 * @return {@link RevocationReason}
	 */
	public static RevocationReason fromValue(final String value) {
		for (RevocationReason reason : RevocationReason.values()) {
			if (reason.shortName.equals(value)) {
				return reason;
			}
		}
		return null;
	}

}
