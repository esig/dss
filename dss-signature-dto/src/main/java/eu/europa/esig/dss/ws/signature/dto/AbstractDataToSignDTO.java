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
package eu.europa.esig.dss.ws.signature.dto;

import java.io.Serializable;
import java.util.Objects;

import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

@SuppressWarnings("serial")
public abstract class AbstractDataToSignDTO implements Serializable {

	private RemoteSignatureParameters parameters;
	
	protected AbstractDataToSignDTO() {
		super();
	}

	protected AbstractDataToSignDTO(RemoteSignatureParameters parameters) {
		super();
		this.parameters = parameters;
	}

	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
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
		AbstractDataToSignDTO other = (AbstractDataToSignDTO) obj;
		if (!Objects.equals(parameters, other.parameters)) {
			return false;
		}
		return true;
	}

}
