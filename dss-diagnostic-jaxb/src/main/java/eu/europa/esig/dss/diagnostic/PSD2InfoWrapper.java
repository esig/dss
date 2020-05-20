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
