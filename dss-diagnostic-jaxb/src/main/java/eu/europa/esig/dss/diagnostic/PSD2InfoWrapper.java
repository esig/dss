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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2QcInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRoleOfPSP;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;

import java.util.ArrayList;
import java.util.List;

/**
 * The wrapper provides a user-friendly interface for dealing with {@code XmlPSD2QcInfo}
 */
public class PSD2InfoWrapper {

	/** The wrapped {@code XmlPSD2QcInfo} object */
	private final XmlPSD2QcInfo psd2QcInfo;

	/**
	 * Default constructor
	 *
	 * @param psd2QcInfo {@link XmlPSD2QcInfo}
	 */
	public PSD2InfoWrapper(XmlPSD2QcInfo psd2QcInfo) {
		this.psd2QcInfo = psd2QcInfo;
	}

	/**
	 * Returns names of roles of PSP
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getRoleOfPSPNames() {
		List<String> result = new ArrayList<>();
		List<XmlRoleOfPSP> rolesOfPSP = psd2QcInfo.getRolesOfPSP();
		for (XmlRoleOfPSP roleOfPSP : rolesOfPSP) {
			result.add(roleOfPSP.getName());
		}
		return result;
	}

	/**
	 * Returns OIDs of roles of PSP
	 *
	 * @return a list of {@link RoleOfPspOid}s
	 */
	public List<RoleOfPspOid> getRoleOfPSPOids() {
		List<RoleOfPspOid> result = new ArrayList<>();
		List<XmlRoleOfPSP> rolesOfPSP = psd2QcInfo.getRolesOfPSP();
		for (XmlRoleOfPSP roleOfPSP : rolesOfPSP) {
			XmlOID pspOid = roleOfPSP.getOid();
			if (pspOid != null) {
				result.add(RoleOfPspOid.fromOid(pspOid.getValue()));
			}
		}
		return result;
	}

	/**
	 * Returns the Competent Authority Id
	 *
	 * @return {@link String}
	 */
	public String getNcaId() {
		return psd2QcInfo.getNcaId();
	}

	/**
	 * Returns the Competent Authority name
	 *
	 * @return {@link String}
	 */
	public String getNcaName() {
		return psd2QcInfo.getNcaName();
	}

}
