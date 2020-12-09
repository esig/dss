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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.EndorsementType;

import java.util.Date;

/**
 * This class represents the signer roles extracted from the signature.
 */
public class SignerRole {

	/** The role string */
    private final String role;

    /** The category of the role (certified, claimed, signed) */
    private final EndorsementType category;

    /** The certificate's 'notBefore' date for a 'certified' role category */
    private Date notBefore;

	/** The certificate's 'notAfter' date for a 'certified' role category */
    private Date notAfter;

	/**
	 * The default constructor
	 *
	 * @param role {@link String}
	 * @param category {@link EndorsementType} of the SignedRole
	 */
	public SignerRole(String role, EndorsementType category) {
    	this.role = role;
    	this.category = category;
    }

	/**
	 * Gets the role
	 *
	 * @return {@link String}
	 */
	public String getRole() {
        return role;
    }

	/**
	 * Gets the role category
	 *
	 * @return {@link EndorsementType}
	 */
	public EndorsementType getCategory() {
		return category;
	}

	/**
	 * Gets the certificate's 'notBefore' for a 'certified' role category
	 *
	 * @return {@link Date}
	 */
	public Date getNotBefore() {
        return notBefore;
    }

	/**
	 * Sets the certificate's 'notBefore' for a 'certified' role category
	 *
	 * @param notBefore {@link Date}
	 */
	public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

	/**
	 * Gets the certificate's 'notAfter' for a 'certified' role category
	 *
	 * @return {@link Date}
	 */
    public Date getNotAfter() {
        return notAfter;
    }

	/**
	 * Sets the certificate's 'notAfter' for a 'certified' role category
	 *
	 * @param notAfter {@link Date}
	 */
    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

	@Override
	public String toString() {
		return "SignerRole [category=" + category.name() + ", role details=" + role + ", notBefore=" + notBefore +", notAfter=" + notAfter + "]";
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SignerRole)) {
			return false;
		}
		SignerRole s = (SignerRole) obj;
		if (!category.equals(s.category)) {
			return false;
		}
		if (!role.equals(s.role)) {
			return false;
		}
		if ((notBefore == null && s.notBefore != null) || 
				(notBefore != null && !notBefore.equals(s.notBefore))) {
			return false;
		}
		if ((notAfter == null && s.notAfter != null) || 
				(notAfter != null && !notAfter.equals(s.notAfter))) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((role == null) ? 0 : role.hashCode());
		result = (prime * result) + ((category == null) ? 0 : category.hashCode());
		result = (prime * result) + ((notBefore == null) ? 0 : notBefore.hashCode());
		result = (prime * result) + ((notAfter == null) ? 0 : notAfter.hashCode());
		return result;
	}
    
}
