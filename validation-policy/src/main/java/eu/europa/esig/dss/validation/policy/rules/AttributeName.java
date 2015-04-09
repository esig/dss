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
package eu.europa.esig.dss.validation.policy.rules;

public interface AttributeName {

	public static final String CATEGORY = "Category";
	public static final String CERTIFIED_ROLES = "CertifiedRoles";
	public static final String CONSTRAINT_VALUE = "ConstraintValue";
	public static final String CONTEXT = "Context";
	public static final String SUB_CONTEXT = "SubContext";
	public static final String DATE = "Date";
	public static final String EXPECTED_VALUE = "ExpectedValue";
	public static final String FIELD = "Field";
	public static final String GENERATION_TIME = "GenerationTime";
	public static final String ID = "Id";
	public static final String TYPE = "Type";
	public static final String MAXIMUM_REVOCATION_FRESHNESS = "MaximumRevocationFreshness";
	public static final String NAME_ID = "NameId";
	public static final String REQUESTED_ROLES = "RequestedRoles";
	public static final String REVOCATION_ISSUING_TIME = "RevocationIssuingTime";
	public static final String REVOCATION_NEXT_UPDATE = "RevocationNextUpdate";
	public static final String REVOCATION_REASON = "RevocationReason";
	public static final String REVOCATION_TIME = "RevocationTime";
	public static final String SIZE = "Size";
	public static final String TIMESTAMP_TYPE = "Type";
	public static final String PARENT_ID = "ParentId";
}
