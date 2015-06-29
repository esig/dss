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
package eu.europa.esig.dss.cades.validation;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.util.Store;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;

/**
 * CRLSource that retrieves information from a CAdES signature.
 *
 *
 */

public class CAdESCRLSource extends OfflineCRLSource {

    private final CMSSignedData cmsSignedData;
    private final SignerInformation signerInformation;


    /**
     * The default constructor for CAdESCRLSource.
     *
     * @param signerInformation
     */
    public CAdESCRLSource(final CMSSignedData cmsSignedData, final SignerInformation signerInformation) {
        this.cmsSignedData = cmsSignedData;
        this.signerInformation = signerInformation;
        extract();
    }

    private void extract() {

        x509CRLList = new ArrayList<X509CRL>();

        // Adds CRLs contained in SignedData
        final Store crLs = cmsSignedData.getCRLs();
        final Collection<X509CRLHolder> collection = (Collection<X509CRLHolder>) crLs.getMatches(null);
        for (final X509CRLHolder x509CRLHolder : collection) {

            final X509CRL x509CRL = DSSUtils.toX509CRL(x509CRLHolder);
            addCRLToken(x509CRL);
        }

        // Adds CRLs in -XL ... inside SignerInfo attribute if present
        if (signerInformation != null) {

            final AttributeTable attributes = signerInformation.getUnsignedAttributes();
            if (attributes != null) {
                /*
                ETSI TS 101 733 V2.2.1 (2013-04) page 43
                6.3.4 revocation-values Attribute Definition
                This attribute is used to contain the revocation information required for the following forms of extended electronic
                signature: CAdES-X Long, ES X-Long Type 1, and CAdES-X Long Type 2, see clause B.1.1 for an illustration of
                this form of electronic signature.
                The revocation-values attribute is an unsigned attribute. Only a single instance of this attribute shall occur with
                an electronic signature. It holds the values of CRLs and OCSP referenced in the
                complete-revocation-references attribute.

                RevocationValues ::= SEQUENCE {
                crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
                ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
                otherRevVals [2] OtherRevVals OPTIONAL}
                 */
                final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
                if (attribute != null) {

                    final ASN1Set attrValues = attribute.getAttrValues();

                    final ASN1Encodable attValue = attrValues.getObjectAt(0);
                    final RevocationValues revValues = RevocationValues.getInstance(attValue);
                    for (final CertificateList revValue : revValues.getCrlVals()) {

                        addCRLToken(revValue);
                    }
                }
            }

            /* TODO (pades): Read revocation data from from unsigned attribute  1.2.840.113583.1.1.8
              In the PKCS #7 object of a digital signature in a PDF file, identifies a signed attribute
              that "can include all the revocation information that is necessary to carry out revocation
              checks for the signer's certificate and its issuer certificates."
              Defined as adbe-revocationInfoArchival { adbe(1.2.840.113583) acrobat(1) security(1) 8 } in "PDF Reference, fifth edition: Adobe® Portable Document Format, Version 1.6" Adobe Systems Incorporated, 2004.
              http://partners.adobe.com/public/developer/en/pdf/PDFReference16.pdf page 698

              RevocationInfoArchival ::= SEQUENCE {
                crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
                ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
                otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL
              }
              OtherRevInfo ::= SEQUENCE {
                Type OBJECT IDENTIFIER
                Value OCTET STRING
              }
            */


            // TODO: (Bob: 2013 Dec 03) --> NICOLAS: Is there any other container within the CAdES signature with revocation data? (ie: timestamp)
        }
    }

    private void addCRLToken(final X509CRL x509CRL) {

        if (!x509CRLList.contains(x509CRL)) {

            x509CRLList.add(x509CRL);
        }
    }

    private void addCRLToken(final CertificateList certificateList) {

        final X509CRLObject x509CRLObject = getX509CRLObject(certificateList);
        if (!x509CRLList.contains(x509CRLObject)) {

            x509CRLList.add(x509CRLObject);
        }
    }

    private static X509CRLObject getX509CRLObject(final CertificateList certificateList) throws DSSException {

        try {
            return new X509CRLObject(certificateList);
        } catch (CRLException e) {
            throw new DSSException(e);
        }
    }
}
