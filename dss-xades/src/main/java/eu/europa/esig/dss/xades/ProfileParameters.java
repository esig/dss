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

import java.io.Serializable;

/**
 * This class This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the generation.<br>
 */
public class ProfileParameters implements Serializable {

	private SignatureProfile profile;

	/**
	 * Returns the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public SignatureProfile getProfile() {
		return profile;
	}

	/**
	 * Sets the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public void setProfile(SignatureProfile profile) {
		this.profile = profile;
	}

	/*
	 * The builder used to create the signature structure. Currently used only for XAdES.
	 */
	private SignatureBuilder builder;

	public SignatureBuilder getBuilder() {
		return builder;
	}

	public void setBuilder(SignatureBuilder builder) {
		this.builder = builder;
	}

	/*
	 * The type of operation to perform.
	 */
	public static enum Operation {
		SIGNING, EXTENDING
	}

	/*
	 * Indicates the type of the operation to be done
	 */
	private Operation operationKind;

	public Operation getOperationKind() {
		return operationKind;
	}

	public void setOperationKind(Operation operationKind) {
		this.operationKind = operationKind;
	}

}
