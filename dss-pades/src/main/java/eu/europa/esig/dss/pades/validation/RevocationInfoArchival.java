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
package eu.europa.esig.dss.pades.validation;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.esf.OtherRevVals;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;

import java.util.Enumeration;

/**
 * <pre>
 * RevocationInfoArchival ::= SEQUENCE {
 *   crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
 *   ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
 *   otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL
 * }
 * </pre>
 */
public class RevocationInfoArchival
    extends ASN1Object
{

    /** The CRL values */
    private ASN1Sequence crlVals;

    /** The OCSP values */
    private ASN1Sequence ocspVals;

    /** The other revocation values */
    private OtherRevVals otherRevVals;

    /**
     * Gets the {@code RevocationInfoArchival} objet
     *
     * @param obj representing the {@link RevocationInfoArchival}
     * @return {@link RevocationInfoArchival} if the object of the correct type, null otherwise
     */
    public static RevocationInfoArchival getInstance(Object obj)
    {
        if (obj instanceof RevocationInfoArchival)
        {
            return (RevocationInfoArchival)obj;
        }
        else if (obj != null)
        {
            return new RevocationInfoArchival(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private RevocationInfoArchival(ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();
            switch (o.getTagNo())
            {
                case 0:
                    ASN1Sequence crlValsSeq = (ASN1Sequence)o.getBaseObject();
                    Enumeration crlValsEnum = crlValsSeq.getObjects();
                    while (crlValsEnum.hasMoreElements())
                    {
                        CertificateList.getInstance(crlValsEnum.nextElement());
                    }
                    this.crlVals = crlValsSeq;
                    break;
                case 1:
                    ASN1Sequence ocspValsSeq = (ASN1Sequence)o.getBaseObject();
                    Enumeration ocspValsEnum = ocspValsSeq.getObjects();
                    while (ocspValsEnum.hasMoreElements())
                    {
                        OCSPResponse.getInstance(ocspValsEnum.nextElement());
                    }
                    this.ocspVals = ocspValsSeq;
                    break;
                case 2:
                    this.otherRevVals = OtherRevVals.getInstance(o.getBaseObject());
                    break;
                default:
                    throw new IllegalArgumentException("invalid tag: "
                        + o.getTagNo());
            }
        }
    }

    /**
     * The constructor
     *
     * @param crlVals a list of CRL values
     * @param ocspVals a list of OCSP responses
     * @param otherRevVals a list of other revocation values
     */
    public RevocationInfoArchival(CertificateList[] crlVals, OCSPResponse[] ocspVals, OtherRevVals otherRevVals)
    {
        if (null != crlVals)
        {
            this.crlVals = new DERSequence(crlVals);
        }
        if (null != ocspVals)
        {
            this.ocspVals = new DERSequence(ocspVals);
        }
        this.otherRevVals = otherRevVals;
    }

    /**
     * Gets the CRL values
     *
     * @return array of {@link CertificateList}s
     */
    public CertificateList[] getCrlVals()
    {
        if (null == this.crlVals)
        {
            return new CertificateList[0];
        }
        CertificateList[] result = new CertificateList[this.crlVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = CertificateList.getInstance(this.crlVals
                .getObjectAt(idx));
        }
        return result;
    }

    /**
     * Gets the OCSP values
     *
     * @return array of {@link OCSPResponse}s
     */
    public OCSPResponse[] getOcspVals()
    {
        if (null == this.ocspVals)
        {
            return new OCSPResponse[0];
        }
        OCSPResponse[] result = new OCSPResponse[this.ocspVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = OCSPResponse.getInstance(this.ocspVals
                .getObjectAt(idx));
        }
        return result;
    }

    /**
     * Gets the other revocation values
     *
     * @return {@link OtherRevVals}
     */
    public OtherRevVals getOtherRevVals()
    {
        return this.otherRevVals;
    }

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (null != this.crlVals)
        {
            v.add(new DERTaggedObject(true, 0, this.crlVals));
        }
        if (null != this.ocspVals)
        {
            v.add(new DERTaggedObject(true, 1, this.ocspVals));
        }
        if (null != this.otherRevVals)
        {
            v.add(new DERTaggedObject(true, 2, this.otherRevVals.toASN1Primitive()));
        }
        return new DERSequence(v);
    }

}
