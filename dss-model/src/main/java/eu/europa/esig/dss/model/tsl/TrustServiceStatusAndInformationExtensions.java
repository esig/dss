/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.timedependent.BaseTimeDependent;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Defines information for a TrustService
 */
public class TrustServiceStatusAndInformationExtensions extends BaseTimeDependent {

	private static final long serialVersionUID = 7869738443424437560L;

	/*
	 * Key = lang
	 * 
	 * List = values / lang
	 */

	/** Map of names */
	private final Map<String, List<String>> names;

	/** The type */
	private final String type;

	/** Status */
	private final String status;

	/** A list of condition for qualifiers */
	private final List<ConditionForQualifiers> conditionsForQualifiers;

	/** Additional service info urls */
	private final List<String> additionalServiceInfoUris;

	/** List of service supply points */
	private final List<String> serviceSupplyPoints;

	/** The expired certs revocation info date */
	private final Date expiredCertsRevocationInfo;

	/**
	 * Default constructor
	 *
	 * @param builder {@link TrustServiceStatusAndInformationExtensionsBuilder}
	 */
	public TrustServiceStatusAndInformationExtensions(TrustServiceStatusAndInformationExtensionsBuilder builder) {
		super(builder != null ? builder.startDate : null, builder != null ? builder.endDate : null);
		Objects.requireNonNull(builder, "TrustServiceStatusAndInformationExtensionsBuilder cannot be null!");

		this.names = builder.names;
		this.type = builder.type;
		this.status = builder.status;
		this.conditionsForQualifiers = builder.conditionsForQualifiers;
		this.additionalServiceInfoUris = builder.additionalServiceInfoUris;
		this.serviceSupplyPoints = builder.serviceSupplyPoints;
		this.expiredCertsRevocationInfo = builder.expiredCertsRevocationInfo;
	}

	/**
	 * Gets a map of names
	 *
	 * @return a map of names
	 */
	public Map<String, List<String>> getNames() {
		return names;
	}

	/**
	 * Gets type
	 *
	 * @return {@link String}
	 */
	public String getType() {
		return type;
	}

	/**
	 * Gets status
	 *
	 * @return {@link String}
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Gets a list of conditions for qualifiers
	 *
	 * @return a list of {@link ConditionForQualifiers}
	 */
	public List<ConditionForQualifiers> getConditionsForQualifiers() {
		return conditionsForQualifiers;
	}

	/**
	 * Gets additional service info urls
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	/**
	 * Gets service supply points
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getServiceSupplyPoints() {
		return serviceSupplyPoints;
	}

	/**
	 * Gets the expired certs revocation info date
	 *
	 * @return {@link Date}
	 */
	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

	/**
	 * Builds {@code TrustServiceStatusAndInformationExtensions}
	 */
	public static final class TrustServiceStatusAndInformationExtensionsBuilder {

		/** Map of names */
		private Map<String, List<String>> names;

		/** The type */
		private String type;

		/** Status */
		private String status;

		/** A list of condition for qualifiers */
		private List<ConditionForQualifiers> conditionsForQualifiers;

		/** Additional service info urls */
		private List<String> additionalServiceInfoUris;

		/** List of service supply points */
		private List<String> serviceSupplyPoints;

		/** The expired certs revocation info date */
		private Date expiredCertsRevocationInfo;

		/** The start of validity date */
		private Date startDate;

		/** The end of validity date */
		private Date endDate;

		/**
		 * Default constructor
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder() {
			// empty
		}

		/**
		 * Constructor with {@code TrustServiceStatusAndInformationExtensions}
		 *
		 * @param status {@link TrustServiceStatusAndInformationExtensions}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder(TrustServiceStatusAndInformationExtensions status) {
			this.names = status.getNames();
			this.type = status.getType();
			this.status = status.getStatus();
			this.conditionsForQualifiers = status.getConditionsForQualifiers();
			this.additionalServiceInfoUris = status.getAdditionalServiceInfoUris();
			this.serviceSupplyPoints = status.getServiceSupplyPoints();
			this.expiredCertsRevocationInfo = status.getExpiredCertsRevocationInfo();
			this.startDate = status.getStartDate();
			this.endDate = status.getEndDate();
		}

		/**
		 * Builds {@code TrustServiceStatusAndInformationExtensions}
		 *
		 * @return {@link TrustServiceStatusAndInformationExtensions}
		 */
		public TrustServiceStatusAndInformationExtensions build() {
			return new TrustServiceStatusAndInformationExtensions(this);
		}

		/**
		 * Sets a map of names
		 *
		 * @param names a map of names
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setNames(Map<String, List<String>> names) {
			this.names = names;
			return this;
		}

		/**
		 * Sets a type
		 *
		 * @param type {@link String}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setType(String type) {
			this.type = type;
			return this;
		}

		/**
		 * Sets a status
		 *
		 * @param status {@link String}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setStatus(String status) {
			this.status = status;
			return this;
		}

		/**
		 * Sets conditions for qualifiers
		 *
		 * @param conditionsForQualifiers a list of {@link ConditionForQualifiers}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setConditionsForQualifiers(List<ConditionForQualifiers> conditionsForQualifiers) {
			this.conditionsForQualifiers = conditionsForQualifiers;
			return this;
		}

		/**
		 * Sets additional service info urls
		 *
		 * @param additionalServiceInfoUris a list of {@link String}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setAdditionalServiceInfoUris(List<String> additionalServiceInfoUris) {
			this.additionalServiceInfoUris = additionalServiceInfoUris;
			return this;
		}

		/**
		 * Sets the service supply points
		 *
		 * @param serviceSupplyPoints a list of {@link String}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setServiceSupplyPoints(List<String> serviceSupplyPoints) {
			this.serviceSupplyPoints = serviceSupplyPoints;
			return this;
		}

		/**
		 * Sets the expired certs revocation info date
		 *
		 * @param expiredCertsRevocationInfo {@link Date}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setExpiredCertsRevocationInfo(Date expiredCertsRevocationInfo) {
			this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
			return this;
		}

		/**
		 * Sets the start of validity date
		 *
		 * @param date {@link Date}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setStartDate(Date date) {
			this.startDate = date;
			return this;
		}

		/**
		 * Sets the end of validity date
		 *
		 * @param date {@link Date}
		 * @return this {@link TrustServiceStatusAndInformationExtensionsBuilder}
		 */
		public TrustServiceStatusAndInformationExtensionsBuilder setEndDate(Date date) {
			this.endDate = date;
			return this;
		}
		
	}

	@Override
	public String toString() {
		return "TrustServiceStatusAndInformationExtensions [" +
				"names=" + names +
				", type='" + type + '\'' +
				", status='" + status + '\'' +
				", conditionsForQualifiers=" + conditionsForQualifiers +
				", additionalServiceInfoUris=" + additionalServiceInfoUris +
				", serviceSupplyPoints=" + serviceSupplyPoints +
				", expiredCertsRevocationInfo=" + expiredCertsRevocationInfo +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) return true;
		if (object == null || getClass() != object.getClass()) return false;
		if (!super.equals(object)) return false;

		TrustServiceStatusAndInformationExtensions that = (TrustServiceStatusAndInformationExtensions) object;
		return Objects.equals(names, that.names)
				&& Objects.equals(type, that.type)
				&& Objects.equals(status, that.status)
				&& Objects.equals(conditionsForQualifiers, that.conditionsForQualifiers)
				&& Objects.equals(additionalServiceInfoUris, that.additionalServiceInfoUris)
				&& Objects.equals(serviceSupplyPoints, that.serviceSupplyPoints)
				&& Objects.equals(expiredCertsRevocationInfo, that.expiredCertsRevocationInfo);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(names);
		result = 31 * result + Objects.hashCode(type);
		result = 31 * result + Objects.hashCode(status);
		result = 31 * result + Objects.hashCode(conditionsForQualifiers);
		result = 31 * result + Objects.hashCode(additionalServiceInfoUris);
		result = 31 * result + Objects.hashCode(serviceSupplyPoints);
		result = 31 * result + Objects.hashCode(expiredCertsRevocationInfo);
		return result;
	}

}
