/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.cades;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ocsp.OfflineOCSPSource;

/**
 * OCSPSource that retrieves information from a CAdESSignature.
 *
 * @version $Revision$ - $Date$
 */

public class CAdESOCSPSource extends OfflineOCSPSource {

    private CMSSignedData cmsSignedData;
    private SignerInformation signerInformation;

    /**
     * The default constructor for CAdESOCSPSource.
     *
     * @param cms
     * @throws CMSException
     */
    public CAdESOCSPSource(final CMSSignedData cms, final SignerInformation signerInformation) {

        this.cmsSignedData = cms;
        this.signerInformation = signerInformation;
    }

    @Override
    public List<BasicOCSPResp> getContainedOCSPResponses() {

        final List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();

        // Add OCSPs from SignedData
        {
            final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
            final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
            final ASN1Encodable[] matches = (ASN1Encodable[]) otherRevocationInfoMatches.toArray(new ASN1Encodable[otherRevocationInfoMatches.size()]);
            for (final ASN1Encodable asn1Encodable : matches) {
                final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(asn1Encodable);
                final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
                list.add(basicOCSPResp);
            }
        }
        {
            final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
            final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
            final ASN1Encodable[] matches = (ASN1Encodable[]) otherRevocationInfoMatches.toArray(new ASN1Encodable[otherRevocationInfoMatches.size()]);
            for (final ASN1Encodable asn1Encodable : matches) {
                final OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1Encodable);
                final OCSPResp ocspResp = new OCSPResp(ocspResponse);
                try {
                    final Object responseObject = ocspResp.getResponseObject();
                    if (responseObject instanceof BasicOCSPResp) {
                        BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;
                        list.add(basicOCSPResp);
                    }
                } catch (OCSPException e) {
                    throw new DSSException(e);
                }
            }
        }


        // Adds OCSP responses in -XL id_aa_ets_revocationValues inside SignerInfo attribute if present
        if (signerInformation != null) {

            final AttributeTable attributes = signerInformation.getUnsignedAttributes();
            if (attributes != null) {

                final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
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
                if (attribute != null) {

                    final ASN1Set attrValues = attribute.getAttrValues();
                    final ASN1Encodable attValue = attrValues.getObjectAt(0);
                    final RevocationValues revValues = RevocationValues.getInstance(attValue);

                    for (final BasicOCSPResponse revValue : revValues.getOcspVals()) {
                        final BasicOCSPResp ocspResp = new BasicOCSPResp(revValue);
                        list.add(ocspResp);
                    }
                    /* TODO: should add also OtherRevVals, but:
                     "The syntax and semantics of the other revocation values (OtherRevVals) are outside the scope of the present
                    document. The definition of the syntax of the other form of revocation information is as identified by
                    OtherRevRefType."
                    */
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
        return list;
    }
}
