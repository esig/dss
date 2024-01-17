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

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Contains certificates for the url location
 */
public class OtherTSLPointer implements Serializable {

	private static final long serialVersionUID = 3015076999802292662L;

	/** List of ServiceDigitalIdentity X509 certificates */
	private List<CertificateToken> sdiCertificates;

	/** URL location */
	private String tslLocation;

	/** An ISO code of the country or an alliance */
	private String schemeTerritory;

	/** Type of the Trusted List */
	private String tslType;

	/** MimeType of the Trusted List document */
	private String mimeType;

	/** A map of defined scheme operator names between the used languages */
	private Map<String, List<String>> schemeOperatorNames;

	/** A map of defined type community rules between the used languages */
	private Map<String, List<String>> schemeTypeCommunityRules;

	/** Mutual Recognition Agreement block */
	private MRA mra;

	/**
	 * Default constructor to create an empty object
	 */
	public OtherTSLPointer() {
		// empty
	}

	/**
	 * Default constructor to instantiate object from {@code OtherTSLPointerBuilder}
	 *
	 * @param builder {@link OtherTSLPointerBuilder}
	 */
	public OtherTSLPointer(OtherTSLPointerBuilder builder) {
		this.sdiCertificates = builder.getSdiCertificates();
		this.tslLocation = builder.getTslLocation();
		this.schemeTerritory = builder.getSchemeTerritory();
		this.tslType = builder.getTslType();
		this.mimeType = builder.getMimeType();
		this.schemeOperatorNames = builder.getSchemeOperatorNames();
		this.schemeTypeCommunityRules = builder.getSchemeTypeCommunityRules();
		this.mra = builder.getMra();
	}

	/**
	 * Gets a list of ServiceDigitalIdentity X509 certificates
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getSdiCertificates() {
		return sdiCertificates;
	}

	/**
	 * Gets TSL location url
	 *
	 * @return {@link String}
	 */
	public String getTSLLocation() {
		return tslLocation;
	}

	/**
	 * Gets the scheme territory ISO country code
	 *
	 * @return {@link String}
	 */
	public String getSchemeTerritory() {
		return schemeTerritory;
	}

	/**
	 * Gets the TSL Type
	 *
	 * @return {@link String}
	 */
	public String getTslType() {
		return tslType;
	}

	/**
	 * Gets the MimeType of the referenced document
	 *
	 * @return {@link String}
	 */
	public String getMimeType() {
		return mimeType;
	}

	/**
	 * Gets a map of scheme operator names
	 *
	 * @return a map of {@link String} language code and a list of corresponding {@link String} names
	 */
	public Map<String, List<String>> getSchemeOperatorNames() {
		return schemeOperatorNames;
	}

	/**
	 * Gets a map of scheme type community rules
	 *
	 * @return a map of {@link String} language code and a list of corresponding {@link String} names
	 */
	public Map<String, List<String>> getSchemeTypeCommunityRules() {
		return schemeTypeCommunityRules;
	}

	/**
	 * Gets a Mutual Recognition Agreement block
	 *
	 * @return {@link MRA}
	 */
	public MRA getMra() {
		return mra;
	}

	/**
	 * Builds {@code OtherTSLPointer}
	 */
	public static final class OtherTSLPointerBuilder {

		/** List of ServiceDigitalIdentity X509 certificates */
		private List<CertificateToken> sdiCertificates;

		/** URL location */
		private String tslLocation;

		/** An ISO code of the country or an alliance */
		private String schemeTerritory;

		/** Type of the Trusted List */
		private String tslType;

		/** MimeType of the Trusted List document */
		private String mimeType;

		/** A map of defined scheme operator names between the used languages */
		private Map<String, List<String>> schemeOperatorNames;

		/** A map of defined type community rules between the used languages */
		private Map<String, List<String>> schemeTypeCommunityRules;

		/** Mutual Recognition Agreement block */
		private MRA mra;

		/**
		 * Default constructor
		 */
		public OtherTSLPointerBuilder() {
			// empty
		}

		/**
		 * Gets the ServiceDigitalIdentity X509 certificates
		 *
		 * @return a list of {@link CertificateToken}s
		 */
		public List<CertificateToken> getSdiCertificates() {
			return sdiCertificates;
		}

		/**
		 * Sets the ServiceDigitalIdentity X509 certificates
		 *
		 * @param sdiCertificates a list of {@link CertificateToken}s
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setSdiCertificates(List<CertificateToken> sdiCertificates) {
			this.sdiCertificates = sdiCertificates;
			return this;
		}

		/**
		 * Gets the TSL location URL
		 *
		 * @return tslLocation {@link String}
		 */
		public String getTslLocation() {
			return tslLocation;
		}

		/**
		 * Sets the TSL location URL
		 *
		 * @param tslLocation {@link String}
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setTslLocation(String tslLocation) {
			this.tslLocation = tslLocation;
			return this;
		}

		/**
		 * Gets the scheme territory code
		 *
		 * @return {@link String}
		 */
		public String getSchemeTerritory() {
			return schemeTerritory;
		}

		/**
		 * Sets the scheme territory code
		 *
		 * @param schemeTerritory {@link String}
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setSchemeTerritory(String schemeTerritory) {
			this.schemeTerritory = schemeTerritory;
			return this;
		}

		/**
		 * Gets the TSL Type
		 *
		 * @return {@link String}
		 */
		public String getTslType() {
			return tslType;
		}

		/**
		 * Sets the TSL Type
		 *
		 * @param tslType {@link String}
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setTslType(String tslType) {
			this.tslType = tslType;
			return this;
		}

		/**
		 * Gets the MimeType of the Trusted List document
		 *
		 * @return {@link String}
		 */
		public String getMimeType() {
			return mimeType;
		}

		/**
		 * Sets the MimeType of the Trusted List document
		 *
		 * @param mimeType {@link String}
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setMimeType(String mimeType) {
			this.mimeType = mimeType;
			return this;
		}

		/**
		 * Gets a map of scheme operator names
		 *
		 * @return a map between {@link String} languages and lists of {@link String} names
		 */
		public Map<String, List<String>> getSchemeOperatorNames() {
			return schemeOperatorNames;
		}

		/**
		 * Sets a map of scheme operator names
		 *
		 * @param schemeOperatorNames a map between {@link String} languages and lists of {@link String} names
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setSchemeOperatorNames(Map<String, List<String>> schemeOperatorNames) {
			this.schemeOperatorNames = schemeOperatorNames;
			return this;
		}

		/**
		 * Gets a map of scheme type community rules
		 *
		 * @return a map between {@link String} languages and lists of {@link String} names
		 */
		public Map<String, List<String>> getSchemeTypeCommunityRules() {
			return schemeTypeCommunityRules;
		}

		/**
		 * Sets a map of scheme type community rules
		 *
		 * @param schemeTypeCommunityRules a map between {@link String} languages and lists of {@link String} names
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setSchemeTypeCommunityRules(Map<String, List<String>> schemeTypeCommunityRules) {
			this.schemeTypeCommunityRules = schemeTypeCommunityRules;
			return this;
		}

		/**
		 * Gets the MRA (Mutual Recognition Agreement) scheme
		 *
		 * @return {@link MRA}
		 */
		public MRA getMra() {
			return mra;
		}

		/**
		 * Sets the MRA (Mutual Recognition Agreement) scheme
		 *
		 * @param mra {@link MRA}
		 * @return {@link OtherTSLPointerBuilder}
		 */
		public OtherTSLPointerBuilder setMra(MRA mra) {
			this.mra = mra;
			return this;
		}

		/**
		 * Builds the {@code OtherTSLPointer}
		 *
		 * @return {@link OtherTSLPointer}
		 */
		public OtherTSLPointer build() {
			return new OtherTSLPointer(this);
		}

	}

}
