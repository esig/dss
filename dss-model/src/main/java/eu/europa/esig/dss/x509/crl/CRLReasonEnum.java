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
package eu.europa.esig.dss.x509.crl;


/**
 * This enum is used to get String value of CRLReason
 * 
 * The CRLReason enumeration.
 * 
 * <pre>
 * CRLReason ::= ENUMERATED {
 *  unspecified             (0),
 *  keyCompromise           (1),
 *  cACompromise            (2),
 *  affiliationChanged      (3),
 *  superseded              (4),
 *  cessationOfOperation    (5),
 *  certificateHold         (6),
 *  removeFromCRL           (8),
 *  privilegeWithdrawn      (9),
 *  aACompromise           (10)
 * }
 * </pre>
 */
public enum CRLReasonEnum {

	unspecified(0),

	keyCompromise(1),

	cACompromise(2),

	affiliationChanged(3),

	superseded(4),

	cessationOfOperation(5),

	certificateHold(6),

	unknow(7),

	removeFromCRL(8),

	privilegeWithdrawn(9),

	aACompromise(10);

	private final int value;

	private CRLReasonEnum(final int value) {
		this.value = value;
	}

	public static CRLReasonEnum fromInt(final int value) {
		for (CRLReasonEnum reason : CRLReasonEnum.values()) {
			if(reason.value == value) {
				return reason;
			}
		}
		return CRLReasonEnum.unknow;
	}

}
