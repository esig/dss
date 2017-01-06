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
package eu.europa.esig.dss.tsl;

import java.io.Serializable;

import eu.europa.esig.dss.util.TimeDependentValues;

/**
 * From a validation point of view, a Service is a set of pair ("Qualification Statement", "Condition").
 *
 */
public class ServiceInfo implements Serializable {

	private static final long serialVersionUID = 4903410679096343832L;

	private String tlCountryCode;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPName>
	 */
	private String tspName;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPTradeName>
	 */
	private String tspTradeName;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPAddress><tsl:PostalAddresses>
	 */
	private String tspPostalAddress;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPAddress><tsl:ElectronicAddress>
	 */
	private String tspElectronicAddress;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceName>
	 */
	private String serviceName;

	private TimeDependentValues<ServiceInfoStatus> status = new TimeDependentValues<ServiceInfoStatus>();

	public String getTlCountryCode() {
		return tlCountryCode;
	}

	public void setTlCountryCode(String tlCountryCode) {
		this.tlCountryCode = tlCountryCode;
	}

	/**
	 * @return
	 */
	public String getServiceName() {
		return serviceName;
	}

	/**
	 * @return
	 */
	public String getTspElectronicAddress() {
		return tspElectronicAddress;
	}

	/**
	 * @return
	 */
	public String getTspName() {
		return tspName;
	}

	/**
	 * @return
	 */
	public String getTspPostalAddress() {
		return tspPostalAddress;
	}

	/**
	 * @return
	 */
	public String getTspTradeName() {
		return tspTradeName;
	}

	/**
	 * @param serviceName
	 */
	public void setServiceName(String serviceName) {
		this.serviceName = trim(serviceName);
	}

	/**
	 * @param tspElectronicAddress
	 */
	public void setTspElectronicAddress(String tspElectronicAddress) {
		this.tspElectronicAddress = trim(tspElectronicAddress);
	}

	/**
	 * @param tspName
	 */
	public void setTspName(String tspName) {
		this.tspName = trim(tspName);
	}

	/**
	 * @param tspPostalAddress
	 */
	public void setTspPostalAddress(String tspPostalAddress) {
		this.tspPostalAddress = trim(tspPostalAddress);
	}

	/**
	 * @param tspTradeName
	 */
	public void setTspTradeName(String tspTradeName) {
		this.tspTradeName = trim(tspTradeName);
	}

	public TimeDependentValues<ServiceInfoStatus> getStatus() {
		return status;
	}

	public void setStatus(TimeDependentValues<ServiceInfoStatus> status) {
		this.status = new TimeDependentValues<ServiceInfoStatus>(status);
	}

	/**
	 * @param indent
	 * @return
	 */
	public String toString(String indent) {
		try {
			StringBuffer buffer = new StringBuffer();
			buffer.append(indent).append("TSPName                   \t= ").append(tspName).append('\n');
			buffer.append(indent).append("ServiceName               \t= ").append(serviceName).append('\n');
			buffer.append(indent).append("StatusAndExtensions       \t= ").append(status).append('\n');
			buffer.append(indent).append("TSPTradeName              \t= ").append(tspTradeName).append('\n');
			buffer.append(indent).append("TSPPostalAddress          \t= ").append(tspPostalAddress).append('\n');
			buffer.append(indent).append("TSPElectronicAddress      \t= ").append(tspElectronicAddress).append("\n\n");
			return buffer.toString();
		} catch (Exception e) {
			return super.toString();
		}
	}

	private String trim(String str) {

		if (str != null) {
			return str.trim();
		}
		return str;
	}

	@Override
	public String toString() {

		return toString("");
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((serviceName == null) ? 0 : serviceName.hashCode());
		result = (prime * result) + ((tspName == null) ? 0 : tspName.hashCode());
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
		ServiceInfo other = (ServiceInfo) obj;
		if (serviceName == null) {
			if (other.serviceName != null) {
				return false;
			}
		} else if (!serviceName.equals(other.serviceName)) {
			return false;
		}
		if (tspName == null) {
			if (other.tspName != null) {
				return false;
			}
		} else if (!tspName.equals(other.tspName)) {
			return false;
		}
		return true;
	}

}
