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
	 * <pre>
	 * {@code
	 * 	<tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPName>
	 * }
	 * </pre>
	 */
	private String tspName;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPTradeName>
	 * }
	 * </pre>
	 */
	private String tspTradeName;

	/**
	 * VAT or NTR
	 * 
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPTradeName><tsl:Name> 
	 * }
	 * </pre>
	 */
	private String tspRegistrationIdentifier;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPAddress><tsl:PostalAddresses>
	 * }
	 * </pre>
	 */
	private String tspPostalAddress;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPAddress><tsl:ElectronicAddress>
	 * }
	 * </pre>
	 */
	private String tspElectronicAddress;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceName>
	 * }
	 * </pre>
	 */
	private String serviceName;

	private TimeDependentValues<ServiceInfoStatus> status = new TimeDependentValues<ServiceInfoStatus>();

	/**
	 * Returns the trusted list country code
	 * 
	 * @return the country code
	 */
	public String getTlCountryCode() {
		return tlCountryCode;
	}

	/**
	 * Returns the status history
	 * 
	 * @return the trust service's status history
	 */
	public TimeDependentValues<ServiceInfoStatus> getStatus() {
		return status;
	}

	/**
	 * Returns the service name
	 * 
	 * @return the service name
	 */
	public String getServiceName() {
		return serviceName;
	}

	/**
	 * Returns the trust service provider's electronic address
	 * 
	 * @return the trust service provider's electronic address
	 */
	public String getTspElectronicAddress() {
		return tspElectronicAddress;
	}

	/**
	 * Returns the trust service provider name
	 * 
	 * @return the trust service provider name
	 */
	public String getTspName() {
		return tspName;
	}

	/**
	 * Returns the trust service VAT or NTR number
	 * 
	 * @return the trust service VAT or NTR number
	 */
	public String getTspRegistrationIdentifier() {
		return tspRegistrationIdentifier;
	}

	/**
	 * Returns the trust service provider's postal address
	 * 
	 * @return the trust service provider's postal address
	 */
	public String getTspPostalAddress() {
		return tspPostalAddress;
	}

	/**
	 * Returns the trust service provider's trade name
	 * 
	 * @return the trust service provider's trade name
	 */
	public String getTspTradeName() {
		return tspTradeName;
	}

	/**
	 * Sets the country code
	 * 
	 * @param tlCountryCode
	 *            the trusted list country code
	 */
	public void setTlCountryCode(String tlCountryCode) {
		this.tlCountryCode = tlCountryCode;
	}

	/**
	 * Sets the service name
	 * 
	 * @param serviceName
	 *            the service name
	 */
	public void setServiceName(String serviceName) {
		this.serviceName = trim(serviceName);
	}

	/**
	 * Sets the electronic address
	 * 
	 * @param tspElectronicAddress
	 *            the electronic address
	 */
	public void setTspElectronicAddress(String tspElectronicAddress) {
		this.tspElectronicAddress = trim(tspElectronicAddress);
	}

	/**
	 * Sets the trust service provider name
	 * 
	 * @param tspName
	 *            the trust service provider's name
	 */
	public void setTspName(String tspName) {
		this.tspName = trim(tspName);
	}

	/**
	 * Sets the trust service VAT / NTR number
	 * 
	 * @param tspRegistrationIdentifier
	 *            the trust service VAT / NTR number
	 */
	public void setTspRegistrationIdentifier(String tspRegistrationIdentifier) {
		this.tspRegistrationIdentifier = tspRegistrationIdentifier;
	}

	/**
	 * Sets the trust service provider's postal address
	 * 
	 * @param tspPostalAddress
	 *            the postal address
	 */
	public void setTspPostalAddress(String tspPostalAddress) {
		this.tspPostalAddress = trim(tspPostalAddress);
	}

	/**
	 * Sets the trust service provider's trade name
	 * 
	 * @param tspTradeName
	 *            the trade name
	 */
	public void setTspTradeName(String tspTradeName) {
		this.tspTradeName = trim(tspTradeName);
	}

	/**
	 * Sets the status history
	 * 
	 * @param status
	 *            the status history
	 */
	public void setStatus(TimeDependentValues<ServiceInfoStatus> status) {
		this.status = new TimeDependentValues<ServiceInfoStatus>(status);
	}

	public String toString(String indent) {
		try {
			StringBuilder buffer = new StringBuilder();
			buffer.append(indent).append("TSPName                   \t= ").append(tspName).append('\n');
			buffer.append(indent).append("ServiceName               \t= ").append(serviceName).append('\n');
			buffer.append(indent).append("StatusAndExtensions       \t= ").append(status).append('\n');
			buffer.append(indent).append("TSPTradeName              \t= ").append(tspTradeName).append('\n');
			buffer.append(indent).append("TSPRegistrationIdentifier \t= ").append(tspRegistrationIdentifier).append('\n');
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
