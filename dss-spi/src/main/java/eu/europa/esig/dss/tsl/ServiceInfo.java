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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * From a validation point of view, a Service is a set of pair ("Qualification Statement", "Condition").
 *
 *
 */

public class ServiceInfo implements Serializable {

	private static final long serialVersionUID = 4903410679096343832L;

	private static final Logger LOG = LoggerFactory.getLogger(ServiceInfo.class);

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
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>
	 */
	private String type;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceName>
	 */
	private String serviceName;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private String status;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:StatusStartingTime>
	 */
	private Date statusStartDate;

	/**
	 * The start date of the previous service history or null if current service
	 */
	private Date statusEndDate;

	private Map<String, List<Condition>> qualifiersAndConditions = new HashMap<String, List<Condition>>();

	private boolean tlWellSigned;

	/**
	 * <tsl:TrustServiceProvider>
	 * - <tsl:TSPServices>
	 * - - <tsl:TSPService>
	 * - - - <tsl:ServiceInformation>
	 * - - - - <tsl:ServiceInformationExtensions>
	 * - - - - - <tsl:Extension Critical="false">
	 * - - - - - - <tsl:ExpiredCertsRevocationInfo>
	 */
	private Date expiredCertsRevocationInfo;

	/**
	 * Add a qualifier and the corresponding conditionEntry
	 *
	 * @param qualifier
	 * @param condition
	 */
	public void addQualifierAndCondition(String qualifier, Condition condition) {

		List<Condition> conditions = qualifiersAndConditions.get(qualifier);
		if (conditions == null) {

			conditions = new ArrayList<Condition>();
			qualifiersAndConditions.put(qualifier, conditions);
		}
		conditions.add(condition);
	}

	/**
	 * Retrieves all the qualifiers for which the corresponding conditionEntry is true.
	 *
	 * @param certificateToken
	 * @return
	 */
	public List<String> getQualifiers(CertificateToken certificateToken) {

		LOG.trace("--> GET_QUALIFIERS()");
		List<String> list = new ArrayList<String>();
		for (Entry<String, List<Condition>> conditionEntry : qualifiersAndConditions.entrySet()) {

			List<Condition> conditions = conditionEntry.getValue();
			LOG.trace("  --> " + conditions);
			for (final Condition condition : conditions) {

				if (condition.check(certificateToken)) {

					LOG.trace("    --> CONDITION TRUE / " + conditionEntry.getKey());
					list.add(conditionEntry.getKey());
					break;
				}
			}
		}
		return list;
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
	public String getStatus() {

		return status;
	}

	/**
	 * @return
	 */
	public Date getStatusEndDate() {

		return statusEndDate;
	}

	/**
	 * @return
	 */
	public Date getStatusStartDate() {

		return statusStartDate;
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
	 * Return the type of the service
	 *
	 * @return
	 */
	public String getType() {

		return type;
	}

	/**
	 * @return the tlWellSigned
	 */
	public boolean isTlWellSigned() {

		return tlWellSigned;
	}

	/**
	 * @param serviceName
	 */
	public void setServiceName(String serviceName) {

		this.serviceName = trim(serviceName);
	}

	/**
	 * @param status
	 */
	public void setStatus(String status) {

		this.status = trim(status);
	}

	/**
	 * @param statusStartDate
	 */
	public void setStatusStartDate(Date statusStartDate) {

		this.statusStartDate = statusStartDate;
	}

	/**
	 * @param statusEndDate
	 */
	public void setStatusEndDate(Date statusEndDate) {

		this.statusEndDate = statusEndDate;
	}

	/**
	 * @param tlWellSigned the tlWellSigned to set
	 */
	public void setTlWellSigned(boolean tlWellSigned) {

		this.tlWellSigned = tlWellSigned;
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

	/**
	 * Define the type of the service
	 *
	 * @param type
	 */
	public void setType(String type) {

		this.type = trim(type);
	}

	public Date getExpiredCertsRevocationInfo() {

		return expiredCertsRevocationInfo;
	}

	public void setExpiredCertsRevocationInfo(Date expiredCertsRevocationInfo) {

		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	/**
	 * @param indent
	 * @return
	 */
	public String toString(String indent) {

		try {

			StringBuffer buffer = new StringBuffer();
			buffer.append(indent).append("Type                      \t= ").append(type).append('\n');
			buffer.append(indent).append("TSPName                   \t= ").append(tspName).append('\n');
			buffer.append(indent).append("ServiceName               \t= ").append(serviceName).append('\n');
			buffer.append(indent).append("Status                    \t= ").append(status).append('\n');
			if (statusStartDate != null) {

				final String startDate = DSSUtils.formatInternal(statusStartDate);
				buffer.append(indent).append("StatusStartDate           \t= ").append(startDate).append('\n');
			}
			if (statusEndDate != null) {

				final String endDate = DSSUtils.formatInternal(statusEndDate);
				buffer.append(indent).append("StatusEndDate           \t= ").append(endDate).append('\n');
			}
			for (final Entry<String, List<Condition>> conditionEntry : qualifiersAndConditions.entrySet()) {

				buffer.append(indent).append("QualifiersAndConditions    \t= ").append(conditionEntry.getKey()).append(":").append('\n');
				indent += "\t\t\t\t\t\t\t\t";

				final List<Condition> conditions = conditionEntry.getValue();
				for (final Condition condition : conditions) {

					buffer.append(condition.toString(indent));
				}
				indent = indent.substring(8);
			}
			buffer.append(indent).append("TSPTradeName              \t= ").append(tspTradeName).append('\n');
			buffer.append(indent).append("TSPPostalAddress          \t= ").append(tspPostalAddress).append('\n');
			buffer.append(indent).append("TSPElectronicAddress      \t= ").append(tspElectronicAddress).append("\n\n");

			if (expiredCertsRevocationInfo != null) {

				final String expiredCertsRevocationInfoDate = DSSUtils.formatInternal(expiredCertsRevocationInfo);
				buffer.append(indent).append("ExpiredCertsRevocationInfo\t= ").append(expiredCertsRevocationInfoDate).append("\n\n");
			}
			buffer.append(indent).append("TLWellSigned              \t= ").append(tlWellSigned).append('\n');
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
		result = prime * result
				+ ((serviceName == null) ? 0 : serviceName.hashCode());
		result = prime * result
				+ ((statusStartDate == null) ? 0 : statusStartDate.hashCode());
		result = prime * result + ((tspName == null) ? 0 : tspName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ServiceInfo other = (ServiceInfo) obj;
		if (serviceName == null) {
			if (other.serviceName != null)
				return false;
		} else if (!serviceName.equals(other.serviceName))
			return false;
		if (statusStartDate == null) {
			if (other.statusStartDate != null)
				return false;
		} else if (!statusStartDate.equals(other.statusStartDate))
			return false;
		if (tspName == null) {
			if (other.tspName != null)
				return false;
		} else if (!tspName.equals(other.tspName))
			return false;
		return true;
	}
	
}
