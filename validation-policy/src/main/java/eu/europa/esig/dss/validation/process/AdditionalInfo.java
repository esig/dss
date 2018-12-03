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
package eu.europa.esig.dss.validation.process;

public final class AdditionalInfo {

	private AdditionalInfo() {
	}

	public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm";

	public static final String CERTIFICATE_VALIDITY = "Certificate validity : {0} to {1}";

	public static final String REVOCATION = "Revocation reason : {0} (date : {1})";

	public static final String KEY_USAGE = "Key usage : {0}";

	public static final String NEXT_UPDATE = "Next update : {0}";

	public static final String CONTROL_TIME = "Control time : {0}";

	public static final String VALIDATION_TIME = "Validation time : {0}";

	public static final String BEST_SIGNATURE_TIME = "Best signature time : {0}";

	public static final String TRUSTED_SERVICE_STATUS = "Status : {0}";

	public static final String TRUSTED_SERVICE_TYPE = "Type : {0}";

	public static final String PSEUDO = "Pseudo : {0}";

	public static final String TRUSTED_LIST = "Trusted List : {0}";

	public static final String TRUST_SERVICE_NAME = "Trust service name : {0}";

}
