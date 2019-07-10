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

import java.util.Date;

import eu.europa.esig.dss.enumerations.EndorsementType;

/**
 * This class represents the signer roles extracted from the signature.
 */
public class SignerRole {

    private final String role;
    private final EndorsementType category;
    private Date notBefore;
    private Date notAfter;
    
    public SignerRole(String role, EndorsementType category) {
    	this.role = role;
    	this.category = category;
    }

    public String getRole() {
        return role;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }
    
    public EndorsementType getCategory() {
    	return category;
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
