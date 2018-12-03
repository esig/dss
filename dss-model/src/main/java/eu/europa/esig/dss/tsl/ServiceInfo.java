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
 * From a validation point of view, a Service is a set of pair ("Qualification
 * Statement", "Condition").
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

	private String trim(String str) {
		if (str != null) {
			return str.trim();
		}
		return str;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("TSPName                   \t= ").append(tspName).append('\n');
		buffer.append("TSPTradeName              \t= ").append(tspTradeName).append('\n');
		buffer.append("TSPRegistrationIdentifier \t= ").append(tspRegistrationIdentifier).append('\n');
		buffer.append("TSPPostalAddress          \t= ").append(tspPostalAddress).append('\n');
		buffer.append("TSPElectronicAddress      \t= ").append(tspElectronicAddress).append("\n\n");
		buffer.append("StatusAndExtensions       \t= ").append(status).append('\n');
		return buffer.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((status == null) ? 0 : status.hashCode());
		result = prime * result + ((tlCountryCode == null) ? 0 : tlCountryCode.hashCode());
		result = prime * result + ((tspElectronicAddress == null) ? 0 : tspElectronicAddress.hashCode());
		result = prime * result + ((tspName == null) ? 0 : tspName.hashCode());
		result = prime * result + ((tspPostalAddress == null) ? 0 : tspPostalAddress.hashCode());
		result = prime * result + ((tspRegistrationIdentifier == null) ? 0 : tspRegistrationIdentifier.hashCode());
		result = prime * result + ((tspTradeName == null) ? 0 : tspTradeName.hashCode());
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
		if (status == null) {
			if (other.status != null) {
				return false;
			}
		} else if (!status.equals(other.status)) {
			return false;
		}
		if (tlCountryCode == null) {
			if (other.tlCountryCode != null) {
				return false;
			}
		} else if (!tlCountryCode.equals(other.tlCountryCode)) {
			return false;
		}
		if (tspElectronicAddress == null) {
			if (other.tspElectronicAddress != null) {
				return false;
			}
		} else if (!tspElectronicAddress.equals(other.tspElectronicAddress)) {
			return false;
		}
		if (tspName == null) {
			if (other.tspName != null) {
				return false;
			}
		} else if (!tspName.equals(other.tspName)) {
			return false;
		}
		if (tspPostalAddress == null) {
			if (other.tspPostalAddress != null) {
				return false;
			}
		} else if (!tspPostalAddress.equals(other.tspPostalAddress)) {
			return false;
		}
		if (tspRegistrationIdentifier == null) {
			if (other.tspRegistrationIdentifier != null) {
				return false;
			}
		} else if (!tspRegistrationIdentifier.equals(other.tspRegistrationIdentifier)) {
			return false;
		}
		if (tspTradeName == null) {
			if (other.tspTradeName != null) {
				return false;
			}
		} else if (!tspTradeName.equals(other.tspTradeName)) {
			return false;
		}
		return true;
	}

}
