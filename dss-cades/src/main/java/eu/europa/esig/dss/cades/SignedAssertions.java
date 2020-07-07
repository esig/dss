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
package eu.europa.esig.dss.cades;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SignedAssertions extends ASN1Object {

    private final List<SignedAssertion> assertions;

    public static SignedAssertions getInstance(Object obj) {
        if (obj instanceof SignedAssertion) {
            return (SignedAssertions) obj;
        } else if (obj != null) {
            return new SignedAssertions(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public SignedAssertions(List<SignedAssertion> assertions) {
        this.assertions = assertions;
    }

    private SignedAssertions(ASN1Sequence seq) {
        assertions = new ArrayList<>(seq.size());
        for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
            assertions.add(SignedAssertion.getInstance(e.nextElement()));
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {

        ASN1EncodableVector v = new ASN1EncodableVector();
        for (SignedAssertion sa : assertions) {
            v.add(sa);
        }

        return new DERSequence(v);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (SignedAssertion sa : assertions) {
            sb.append(sa.toString()).append("\n");
        }

        return sb.toString();
    }

    public List<SignedAssertion> getAssertions() {
        return assertions;
    }
}
