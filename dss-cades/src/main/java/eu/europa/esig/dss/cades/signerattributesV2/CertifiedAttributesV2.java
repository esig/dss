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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;

public class CertifiedAttributesV2 extends ASN1Object {

    private Object[] values;

    public static CertifiedAttributesV2Builder builder() {
        return new CertifiedAttributesV2.CertifiedAttributesV2Builder();
    }

    
    public static CertifiedAttributesV2 getInstance(Object obj) {
        if (obj instanceof AttributeCertificate) {
            return (CertifiedAttributesV2) obj;
        } else if (obj != null) {
            return new CertifiedAttributesV2(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CertifiedAttributesV2(ASN1Sequence seq) {

        int index = 0;
        values = new Object[seq.size()];

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

            switch (taggedObject.getTagNo()) {
                case 0:
                    values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
                    break;
                case 1:
                    values[index] = OtherAttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
                    break;
                default:
                    throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
            }
            index++;
        }
    }

    private CertifiedAttributesV2(CertifiedAttributesV2Builder builder) {

        List<Object> objects = new ArrayList<>();

        if (!builder.attrCerts.isEmpty()) {
            objects.addAll(builder.attrCerts);
        }

        if (!builder.otherAttrCerts.isEmpty()) {
            objects.addAll(builder.attrCerts);
        }

        this.values = objects.toArray();

    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Object obj : values) {

            if (obj instanceof AttributeCertificate) {
                v.add(new DERTaggedObject(0, (AttributeCertificate) obj));
            } else {
                v.add(new DERTaggedObject(1, (OtherAttributeCertificate) obj));
            }
        }

        return new DERSequence(v);
    }

    public static class CertifiedAttributesV2Builder {

        private List<AttributeCertificate> attrCerts = new ArrayList<>();
        private List<OtherAttributeCertificate> otherAttrCerts = new ArrayList<>();

        public CertifiedAttributesV2Builder setAttributeCertificates(List<AttributeCertificate> attCerts) {
            this.attrCerts = attCerts;
            return this;
        }

        public CertifiedAttributesV2Builder addAttributeCertificate(AttributeCertificate attrCert) {
            this.attrCerts.add(attrCert);
            return this;
        }

        public CertifiedAttributesV2Builder setOtherAttributeCertificates(List<OtherAttributeCertificate> otherAttrCerts) {
            this.otherAttrCerts = otherAttrCerts;
            return this;
        }

        public CertifiedAttributesV2Builder addOtherAttributeCertificate(OtherAttributeCertificate otherAttrCert) {
            this.otherAttrCerts.add(otherAttrCert);
            return this;
        }

        public CertifiedAttributesV2 build() {
            return new CertifiedAttributesV2(this);
        }
    }

}
