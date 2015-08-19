package eu.europa.esig.dss.tsl;

import java.util.List;

public class TSLServiceProvider {

	private String name;
	private String tradeName;
	private String postalAddress;
	private String electronicAddress;
	private List<TSLService> services;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getTradeName() {
		return tradeName;
	}

	public void setTradeName(String tradeName) {
		this.tradeName = tradeName;
	}

	public String getPostalAddress() {
		return postalAddress;
	}

	public void setPostalAddress(String postalAddress) {
		this.postalAddress = postalAddress;
	}

	public String getElectronicAddress() {
		return electronicAddress;
	}

	public void setElectronicAddress(String electronicAddress) {
		this.electronicAddress = electronicAddress;
	}

	public List<TSLService> getServices() {
		return services;
	}

	public void setServices(List<TSLService> services) {
		this.services = services;
	}

}
