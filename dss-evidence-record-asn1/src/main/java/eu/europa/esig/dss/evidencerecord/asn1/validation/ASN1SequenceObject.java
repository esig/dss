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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import org.bouncycastle.asn1.tsp.PartialHashtree;

public class ASN1SequenceObject extends DigestValueGroup implements ASN1EvidenceRecordObject {

	private static final long serialVersionUID = -747779213316560098L;

	/** The current partial hash tree object */
    private final PartialHashtree partialHashtree;

    /**
     * Default constructor
     *
     * @param partialHashtree {@link PartialHashtree}
     */
    public ASN1SequenceObject(final PartialHashtree partialHashtree) {
        this.partialHashtree = partialHashtree;
    }

}