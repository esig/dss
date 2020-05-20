package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.RoleOfPspOid;

public class RoleOfPSP {

	private RoleOfPspOid pspOid;
	private String pspName;

	public RoleOfPspOid getPspOid() {
		return pspOid;
	}

	public void setPspOid(RoleOfPspOid pspOid) {
		this.pspOid = pspOid;
	}

	public String getPspName() {
		return pspName;
	}

	public void setPspName(String pspName) {
		this.pspName = pspName;
	}

}
