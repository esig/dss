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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;

/**
 * SignedAssertion ::= SEQUENCE {
 *  signedAssertionID SIGNED-ASSERTION.&id,
 *  signedAssertion SIGNED-ASSERTION.&Assertion OPTIONAL
 * }
 *
 * SIGNED-ASSERTION::= CLASS {
 *  &id OBJECT IDENTIFIER UNIQUE,
 *  &Assertion OPTIONAL }
 *  WITH SYNTAX {
 *  SIGNED-ASSERTION-ID &id
 *  [SIGNED-ASSERTION-TYPE &Assertion] }
 */
public class SignedAssertion extends ASN1Object {

    /** SignedAssertion OID */
    private final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("0.4.0.19122.1.6");

    /** The SignedAssertion value */
    private DERPrintableString assertion;

    /**
     * Parses the object and returns instance of {@code SignedAssertion},
     * null if the object has another type
     *
     * @param obj object representing the {@link SignedAssertion}
     * @return {@link SignedAssertion}
     */
    public static SignedAssertion getInstance(Object obj) {
        if (obj instanceof SignedAssertion) {
            return (SignedAssertion) obj;
        } else if (obj != null) {
            return new SignedAssertion(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    /**
     * Creates the {@code SignedAssertion} from a string value
     *
     * @param assertion {@link String}
     */
    public SignedAssertion(String assertion) {
        this.assertion = new DERPrintableString(assertion);
    }

    private SignedAssertion(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }
        this.assertion = DERPrintableString.getInstance(seq.getObjectAt(1));
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(oid);
        v.add(assertion);

        return new DERSequence(v);
    }
  
    @Override
    public String toString(){
        return assertion.getString();
    }

}
