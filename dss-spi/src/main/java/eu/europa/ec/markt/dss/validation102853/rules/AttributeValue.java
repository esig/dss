/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.rules;

public interface AttributeValue {

	public static final String EXPIRED_CERTS_REVOCATION_INFO = "ExpiredCertsRevocationInfo";
	public static final String REVOCATION = "Revocation";

	public static final String CERTIFICATE = "Certificate";
	public static final String CERTIFICATE_ID = "CertificateId";
	public static final String CERTIFICATE_SOURCE = "CertificateSource";
	public static final String NOT_BEFORE = "NotBefore";
	public static final String NOT_AFTER = "NotAfter";

	public static final String BEST_SIGNATURE_TIME = "BestSignatureTime";
	public static final String CONTROL_TIME = "ControlTime";
	public static final String ALGORITHM_NOT_FOUND = "Algorithm not found";
	public static final String TRUSTED_SERVICE_STATUS = "TrustedServiceStatus";
	public static final String LATEST_CONTENT_TIMESTAMP_PRODUCTION_TIME = "LatestContentTimestampProductionDate";
	public static final String EARLIEST_SIGNATURE_TIMESTAMP_PRODUCTION_TIME = "EarliestSignatureTimestampProductionDate";

	public static final String ALGORITHM_EXPIRATION_DATE = "AlgorithmExpirationDate";

	public static final String ALGORITHM = "Algorithm";
	public static final String ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";
	public static final String DIGEST_ALGORITHM = "DigestAlgorithm";
	public static final String PUBLIC_KEY_SIZE = "PublicKeySize";
	public static final String MINIMUM_PUBLIC_KEY_SIZE = "MinimumPublicKeySize";

	public static final String COUNTERSIGNATURE = "COUNTERSIGNATURE";

}
