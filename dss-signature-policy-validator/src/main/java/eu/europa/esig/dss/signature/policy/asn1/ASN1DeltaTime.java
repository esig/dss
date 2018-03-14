/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.asn1;

import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.integer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import eu.europa.esig.dss.signature.policy.DeltaTime;
/**
 * DeltaTime ::= SEQUENCE {
 *         deltaSeconds    INTEGER,
 *         deltaMinutes    INTEGER,
 *         deltaHours      INTEGER,
 *         deltaDays       INTEGER }
 * @author davyd.santos
 *
 */
public class ASN1DeltaTime extends ASN1Object implements DeltaTime {
	private int deltaSeconds;
	private int deltaMinutes;
	private int deltaHours;
	private int deltaDays;
	
	public static ASN1DeltaTime getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1DeltaTime(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1DeltaTime(ASN1Sequence as) {
		if (as.size() != 4) {
			throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		deltaSeconds = ASN1Integer.getInstance(as.getObjectAt(0)).getValue().intValue();
		deltaMinutes = ASN1Integer.getInstance(as.getObjectAt(1)).getValue().intValue();
		deltaHours = ASN1Integer.getInstance(as.getObjectAt(2)).getValue().intValue();
		deltaDays = ASN1Integer.getInstance(as.getObjectAt(3)).getValue().intValue();
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				integer(deltaSeconds),
				integer(deltaMinutes),
				integer(deltaHours),
				integer(deltaDays));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.DeltaTime#getDeltaSeconds()
	 */
	@Override
	public int getDeltaSeconds() {
		return deltaSeconds;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.DeltaTime#getDeltaMinutes()
	 */
	@Override
	public int getDeltaMinutes() {
		return deltaMinutes;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.DeltaTime#getDeltaHours()
	 */
	@Override
	public int getDeltaHours() {
		return deltaHours;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.DeltaTime#getDeltaDays()
	 */
	@Override
	public int getDeltaDays() {
		return deltaDays;
	}

}
