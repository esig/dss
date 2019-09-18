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
package eu.europa.esig.dss.tsl.dto;

import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.spi.util.BaseTimeDependent;

public class TrustServiceStatusAndInformationExtensions extends BaseTimeDependent {

	/**
	 * Key = lang
	 * 
	 * List = values / lang
	 */
	private Map<String, List<String>> names;

	private String type;
	private String status;
	private List<ConditionForQualifiers> conditionsForQualifiers;
	private List<String> additionalServiceInfoUris;
	private List<String> serviceSupplyPoints;
	private Date expiredCertsRevocationInfo;

	public Map<String, List<String>> getNames() {
		return names;
	}

	public void setNames(Map<String, List<String>> names) {
		this.names = names;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public List<ConditionForQualifiers> getConditionsForQualifiers() {
		return conditionsForQualifiers;
	}

	public void setConditionsForQualifiers(List<ConditionForQualifiers> conditionsForQualifiers) {
		this.conditionsForQualifiers = conditionsForQualifiers;
	}

	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	public void setAdditionalServiceInfoUris(List<String> additionalServiceInfoUris) {
		this.additionalServiceInfoUris = additionalServiceInfoUris;
	}

	public List<String> getServiceSupplyPoints() {
		return serviceSupplyPoints;
	}

	public void setServiceSupplyPoints(List<String> serviceSupplyPoints) {
		this.serviceSupplyPoints = serviceSupplyPoints;
	}

	public void setExpiredCertsRevocationInfo(Date expiredCertsRevocationInfo) {
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

}
