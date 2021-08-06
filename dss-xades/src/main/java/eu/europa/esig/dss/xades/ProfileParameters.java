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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.signature.SigningOperation;

import java.io.Serializable;

/**
 * This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the generation.
 *
 * NOTE: Currently used only for XAdES.
 *
 */
public class ProfileParameters implements Serializable {

	private static final long serialVersionUID = 2655781283234085565L;

	/** The XAdES creation profile */
	private SignatureProfile profile;

	/**
	 * The builder used to create the signature structure.
	 */
	private SignatureBuilder builder;

	/**
	 * Indicates the type of the operation to be done
	 */
	private SigningOperation operationKind;

	/**
	 * Returns the current Profile used to generate the signature or its extension
	 *
	 * @return the SignatureProfile
	 */
	public SignatureProfile getProfile() {
		return profile;
	}

	/**
	 * Sets the current Profile used to generate the signature or its extension
	 * 
	 * @param profile
	 *            the SignatureProfile
	 */
	public void setProfile(SignatureProfile profile) {
		this.profile = profile;
	}

	/**
	 * Gets the signature builder
	 *
	 * @return {@link SignatureBuilder}
	 */
	public SignatureBuilder getBuilder() {
		return builder;
	}

	/**
	 * Sets the signature builder
	 *
	 * @param builder {@link SignatureBuilder}
	 */
	public void setBuilder(SignatureBuilder builder) {
		this.builder = builder;
	}

	/**
	 * Gets the current operation type
	 *
	 * @return {@link SigningOperation}
	 */
	public SigningOperation getOperationKind() {
		return operationKind;
	}

	/**
	 * Sets the operation kind
	 *
	 * @param operationKind {@link SigningOperation}
	 */
	public void setOperationKind(SigningOperation operationKind) {
		this.operationKind = operationKind;
	}

}
