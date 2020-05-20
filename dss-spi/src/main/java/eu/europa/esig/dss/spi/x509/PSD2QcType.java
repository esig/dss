package eu.europa.esig.dss.spi.x509;

import java.util.List;

public class PSD2QcType {

	private List<RoleOfPSP> rolesOfPSP;
	private String ncaName;
	private String ncaId;

	public List<RoleOfPSP> getRolesOfPSP() {
		return rolesOfPSP;
	}

	public void setRolesOfPSP(List<RoleOfPSP> rolesOfPSP) {
		this.rolesOfPSP = rolesOfPSP;
	}

	public String getNcaName() {
		return ncaName;
	}

	public void setNcaName(String ncaName) {
		this.ncaName = ncaName;
	}

	public String getNcaId() {
		return ncaId;
	}

	public void setNcaId(String ncaId) {
		this.ncaId = ncaId;
	}

}
