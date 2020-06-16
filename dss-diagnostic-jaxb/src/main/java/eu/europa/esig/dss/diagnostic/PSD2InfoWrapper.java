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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Info;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Role;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;

public class PSD2InfoWrapper {

	private final XmlPSD2Info psd2Info;

	public PSD2InfoWrapper(XmlPSD2Info psd2Info) {
		this.psd2Info = psd2Info;
	}

	public List<String> getRoleOfPSPNames() {
		List<String> result = new ArrayList<>();
		List<XmlPSD2Role> psd2Roles = psd2Info.getPSD2Roles();
		for (XmlPSD2Role xmlPSD2Role : psd2Roles) {
			result.add(xmlPSD2Role.getPspName());
		}
		return result;
	}

	public List<RoleOfPspOid> getRoleOfPSPOids() {
		List<RoleOfPspOid> result = new ArrayList<>();
		List<XmlPSD2Role> psd2Roles = psd2Info.getPSD2Roles();
		for (XmlPSD2Role xmlPSD2Role : psd2Roles) {
			XmlOID pspOid = xmlPSD2Role.getPspOid();
			if (pspOid != null) {
				result.add(RoleOfPspOid.fromOid(pspOid.getValue()));
			}
		}
		return result;
	}

	public String getNcaId() {
		return psd2Info.getNcaId();
	}

	public String getNcaName() {
		return psd2Info.getNcaName();
	}

}
