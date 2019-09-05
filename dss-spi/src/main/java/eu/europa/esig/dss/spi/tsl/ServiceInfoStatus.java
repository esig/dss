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
package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.spi.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent implements Serializable {

	private static final long serialVersionUID = 4258613511229825596L;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceName>
	 * }
	 * </pre>
	 */
	private final String serviceName;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>
	 * }
	 * </pre>
	 */
	private final String type;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 * }
	 * </pre>
	 */
	private final String status;

	private final Map<String, List<Condition>> qualifiersAndConditions;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceInformationExtensions><tsl:Extension><tsl:AdditionalServiceInformation>
	 * }
	 * </pre>
	 */
	private final List<String> additionalServiceInfoUris;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceSupplyPoints>
	 * }
	 * </pre>
	 */
	private final List<String> serviceSupplyPoints;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceInformationExtensions><tsl:Extension><tsl:ExpiredCertsRevocationInfo>
	 * }
	 * </pre>
	 */
	private final Date expiredCertsRevocationInfo;

	public ServiceInfoStatus(String serviceName, String type, String status,
			Map<String, List<Condition>> qualifiersAndConditions, List<String> additionalServiceInfoUris,
			List<String> serviceSupplyPoints, Date expiredCertsRevocationInfo, Date startDate, Date endDate) {
		super(startDate, endDate);
		this.serviceName = serviceName;
		this.type = type;
		this.status = status;
		this.qualifiersAndConditions = qualifiersAndConditions;
		this.additionalServiceInfoUris = additionalServiceInfoUris;
		this.serviceSupplyPoints = serviceSupplyPoints;
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
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
	 * Returns the ServiceTypeIdentifier
	 * 
	 * @return the ServiceTypeIdentifier
	 */
	public String getType() {
		return type;
	}

	/**
	 * Returns the ServiceStatus
	 * 
	 * @return the ServiceStatus
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Returns a Map of qualifiers with its conditions
	 * 
	 * @return a Map of qualifiers with its conditions
	 */
	public Map<String, List<Condition>> getQualifiersAndConditions() {
		return qualifiersAndConditions;
	}

	/**
	 * Returns a List of AdditionalServiceInformation
	 * 
	 * @return the list of AdditionalServiceInformation
	 */
	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	/**
	 * Returns a list of ServiceSupplyPoints
	 * 
	 * @return the list of ServiceSupplyPoints
	 */
	public List<String> getServiceSupplyPoints() {
		return serviceSupplyPoints;
	}

	/**
	 * Returns the ExpiredCertsRevocationInfo's date
	 * 
	 * @return the date ExpiredCertsRevocationInfo
	 */
	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("ServiceName               \t= ").append(serviceName).append('\n');
		buffer.append("ServiceType               \t= ").append(type).append('\n');
		buffer.append("ServiceStatus             \t= ").append(status).append('\n');
		buffer.append("Dates                     \t= ").append(super.toString()).append('\n');
		return buffer.toString();
	}

}
