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
package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

public class OtherTSLPointer implements Serializable {

	private static final long serialVersionUID = 3015076999802292662L;

	private final String location;
	private final List<CertificateToken> certificates;

	private final MRA mra;

	public OtherTSLPointer(String location, List<CertificateToken> certificates, MRA mra) {
		this.location = location;
		this.certificates = certificates;
		this.mra = mra;
	}

	public String getLocation() {
		return location;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public MRA getMra() {
		return mra;
	}

}
