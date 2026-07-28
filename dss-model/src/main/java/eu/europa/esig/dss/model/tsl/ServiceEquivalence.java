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

import eu.europa.esig.dss.enumerations.MRAStatus;
import eu.europa.esig.dss.model.timedependent.BaseTimeDependent;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class represents a wrapper for TrustServiceEquivalenceInformation element from MRA scheme
 *
 */
public class ServiceEquivalence extends BaseTimeDependent {

	private static final long serialVersionUID = 7729236073848705753L;

	/** TrustServiceLegalIdentifier */
	private String legalInfoIdentifier;

	/** TrustServiceEquivalenceStatus */
	private MRAStatus status;

	/** AdditionalServiceInformation equivalencies */
	private Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence;

	/** TrustServiceTSLStatusEquivalenceList equivalencies */
	private Map<List<String>, List<String>> statusEquivalence;

	/** CertificateContentReferencesEquivalenceList */
	private List<CertificateContentEquivalence> certificateContentEquivalences;

	/** QualifierEquivalenceList equivalencies */
	private Map<String, String> qualifierEquivalence;

	/**
	 * Default constructor instantiating object with values from the builder
	 *
	 * @param builder {@link ServiceEquivalenceBuilder}
	 */
	public ServiceEquivalence(ServiceEquivalenceBuilder builder) {
		super(builder.startDate, builder.endDate);
		this.legalInfoIdentifier = builder.legalInfoIdentifier;
		this.status = builder.status;
		this.typeAsiEquivalence = builder.typeAsiEquivalence;
		this.statusEquivalence = builder.statusEquivalence;
		this.certificateContentEquivalences = builder.certificateContentEquivalences;
		this.qualifierEquivalence = builder.qualifierEquivalence;
	}

	/**
	 * Gets TrustServiceLegalIdentifier value
	 *
	 * @return {@link String}
	 */
	public String getLegalInfoIdentifier() {
		return legalInfoIdentifier;
	}

	/**
	 * Sets TrustServiceLegalIdentifier value
	 *
	 * @param legalInfoIdentifier {@link String}
	 */
	public void setLegalInfoIdentifier(String legalInfoIdentifier) {
		this.legalInfoIdentifier = legalInfoIdentifier;
	}

	/**
	 * Gets TrustServiceEquivalenceStatus value
	 *
	 * @return {@link MRAStatus}
	 */
	public MRAStatus getStatus() {
		return status;
	}

	/**
	 * Sets TrustServiceEquivalenceStatus value
	 *
	 * @param status {@link MRAStatus}
	 */
	public void setStatus(MRAStatus status) {
		this.status = status;
	}

	/**
	 * Gets a map of AdditionalServiceInformation equivalences between pointed and pointing parties
	 *
	 * @return a map between {@link ServiceTypeASi} for pointed and {@link ServiceTypeASi} for pointing parties
	 */
	public Map<ServiceTypeASi, ServiceTypeASi> getTypeAsiEquivalence() {
		return typeAsiEquivalence;
	}

	/**
	 * Sets a map of AdditionalServiceInformation equivalences between pointed and pointing parties
	 *
	 * @param typeAsiEquivalence a map between {@link ServiceTypeASi} for pointed and {@link ServiceTypeASi} for pointing parties
	 */
	public void setTypeAsiEquivalence(Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence) {
		this.typeAsiEquivalence = typeAsiEquivalence;
	}

	/**
	 * Gets a map of TrustServiceTSLStatusEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @return a map between list of {@link String} for pointed and pointing parties
	 */
	public Map<List<String>, List<String>> getStatusEquivalence() {
		return statusEquivalence;
	}

	/**
	 * Sets a map of TrustServiceTSLStatusEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @param statusEquivalence a map between list of {@link String} for pointed and pointing parties
	 */
	public void setStatusEquivalence(Map<List<String>, List<String>> statusEquivalence) {
		this.statusEquivalence = statusEquivalence;
	}

	/**
	 * Gets a list of CertificateContentReferencesEquivalenceList equivalences
	 *
	 * @return a list of {@code CertificateContentEquivalence} values
	 */
	public List<CertificateContentEquivalence> getCertificateContentEquivalences() {
		return certificateContentEquivalences;
	}

	/**
	 * Sets a list of CertificateContentReferencesEquivalenceList equivalences
	 *
	 * @param certificateContentEquivalences a list of {@code CertificateContentEquivalence} values
	 */
	public void setCertificateContentEquivalences(List<CertificateContentEquivalence> certificateContentEquivalences) {
		this.certificateContentEquivalences = certificateContentEquivalences;
	}

	/**
	 * Gets a map of QualifierEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @return a map between {@code String} for pointed and pointing parties
	 */
	public Map<String, String> getQualifierEquivalence() {
		return qualifierEquivalence;
	}

	/**
	 * Sets a map of QualifierEquivalenceList equivalences between pointed and pointing parties
	 *
	 * @param qualifierEquivalence a map between {@code String} for pointed and pointing parties
	 */
	public void setQualifierEquivalence(Map<String, String> qualifierEquivalence) {
		this.qualifierEquivalence = qualifierEquivalence;
	}

	/**
	 * Builder class used to build a {@code ServiceEquivalence} object
	 */
	public static final class ServiceEquivalenceBuilder {

		/**
		 * TrustServiceLegalIdentifier
		 */
		private String legalInfoIdentifier;

		/**
		 * TrustServiceEquivalenceStatus
		 */
		private MRAStatus status;

		/**
		 * TrustServiceEquivalenceStatusStartingTime
		 */
		private Date startDate;

		/**
		 * The start date of the next TrustServiceEquivalenceHistoryInstance or TrustServiceEquivalenceInformationType
		 */
		private Date endDate;

		/**
		 * AdditionalServiceInformation equivalencies
		 */
		private Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence;

		/**
		 * TrustServiceTSLStatusEquivalenceList equivalencies
		 */
		private Map<List<String>, List<String>> statusEquivalence;

		/**
		 * CertificateContentReferencesEquivalenceList
		 */
		private List<CertificateContentEquivalence> certificateContentEquivalences;

		/**
		 * QualifierEquivalenceList equivalencies
		 */
		private Map<String, String> qualifierEquivalence;

		/**
		 * Default constructor instantiating object with null values
		 */
		public ServiceEquivalenceBuilder() {
			// empty
		}

		/**
		 * Builds the {@code ServiceEquivalence} object
		 *
		 * @return {@link ServiceEquivalence}
		 */
		public ServiceEquivalence build() {
			return new ServiceEquivalence(this);
		}

		/**
		 * Sets TrustServiceLegalIdentifier value
		 *
		 * @param legalInfoIdentifier {@link String}
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setLegalInfoIdentifier(String legalInfoIdentifier) {
			this.legalInfoIdentifier = legalInfoIdentifier;
			return this;
		}

		/**
		 * Sets TrustServiceEquivalenceStatus value
		 *
		 * @param status {@link MRAStatus}
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setStatus(MRAStatus status) {
			this.status = status;
			return this;
		}

		/**
		 * Sets TrustServiceEquivalenceStatusStartingTime value
		 *
		 * @param startDate {@link Date}
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setStartDate(Date startDate) {
			this.startDate = startDate;
			return this;
		}

		/**
		 * Sets the endDate (equivalent to the starting date of the following service equivalence) value
		 *
		 * @param endDate {@link Date}
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setEndDate(Date endDate) {
			this.endDate = endDate;
			return this;
		}

		/**
		 * Sets a map of AdditionalServiceInformation equivalences between pointed and pointing parties
		 *
		 * @param typeAsiEquivalence a map between {@link ServiceTypeASi} for pointed and {@link ServiceTypeASi} for pointing parties
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setTypeAsiEquivalence(Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence) {
			this.typeAsiEquivalence = typeAsiEquivalence;
			return this;
		}

		/**
		 * Sets a map of TrustServiceTSLStatusEquivalenceList equivalences between pointed and pointing parties
		 *
		 * @param statusEquivalence a map between list of {@link String} for pointed and pointing parties
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setStatusEquivalence(Map<List<String>, List<String>> statusEquivalence) {
			this.statusEquivalence = statusEquivalence;
			return this;
		}

		/**
		 * Sets a list of CertificateContentReferencesEquivalenceList equivalences
		 *
		 * @param certificateContentEquivalences a list of {@code CertificateContentEquivalence} values
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setCertificateContentEquivalences(List<CertificateContentEquivalence> certificateContentEquivalences) {
			this.certificateContentEquivalences = certificateContentEquivalences;
			return this;
		}

		/**
		 * Sets a map of QualifierEquivalenceList equivalences between pointed and pointing parties
		 *
		 * @param qualifierEquivalence a map between {@code String} for pointed and pointing parties
		 * @return this {@link ServiceEquivalenceBuilder}
		 */
		public ServiceEquivalenceBuilder setQualifierEquivalence(Map<String, String> qualifierEquivalence) {
			this.qualifierEquivalence = qualifierEquivalence;
			return this;
		}

	}

	@Override
	public String toString() {
		return "ServiceEquivalence [" +
				"legalInfoIdentifier='" + legalInfoIdentifier + '\'' +
				", status=" + status +
				", typeAsiEquivalence=" + typeAsiEquivalence +
				", statusEquivalence=" + statusEquivalence +
				", certificateContentEquivalences=" + certificateContentEquivalences +
				", qualifierEquivalence=" + qualifierEquivalence +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) return true;
		if (object == null || getClass() != object.getClass()) return false;
		if (!super.equals(object)) return false;

		ServiceEquivalence that = (ServiceEquivalence) object;
		return Objects.equals(legalInfoIdentifier, that.legalInfoIdentifier)
				&& status == that.status
				&& Objects.equals(typeAsiEquivalence, that.typeAsiEquivalence)
				&& Objects.equals(statusEquivalence, that.statusEquivalence)
				&& Objects.equals(certificateContentEquivalences, that.certificateContentEquivalences)
				&& Objects.equals(qualifierEquivalence, that.qualifierEquivalence);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(legalInfoIdentifier);
		result = 31 * result + Objects.hashCode(status);
		result = 31 * result + Objects.hashCode(typeAsiEquivalence);
		result = 31 * result + Objects.hashCode(statusEquivalence);
		result = 31 * result + Objects.hashCode(certificateContentEquivalences);
		result = 31 * result + Objects.hashCode(qualifierEquivalence);
		return result;
	}

}
