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
package eu.europa.esig.dss.cades.signerattributesV2;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

// not specified yet by etsi
public class OtherAttributeCertificate extends ASN1Object {

    private DERBitString id;
    private ASN1Object otherCert;

    public static OtherAttributeCertificate getInstance(Object obj) {
        if (obj instanceof OtherAttributeCertificate) {
            return (OtherAttributeCertificate) obj;
        } else if (obj != null) {
            return new OtherAttributeCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public OtherAttributeCertificate(
            ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }
        this.id = DERBitString.getInstance(seq.getObjectAt(0));
        this.otherCert = (ASN1Object) seq.getObjectAt(1);

    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(id);
        v.add(otherCert);

        return new DERSequence(v);
    }

}
