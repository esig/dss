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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;

/**
 * OCSPSource that retrieves information from a CAdESSignature.
 *
 *
 */

public class CAdESOCSPSource extends OfflineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESOCSPSource.class);

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

		final List<BasicOCSPResp> basicOCSPResps = new ArrayList<BasicOCSPResp>();
		// Add OCSPs from SignedData
		addBasicOcspRespFrom_id_pkix_ocsp_basic(basicOCSPResps);
		addBasicOcspRespFrom_id_ri_ocsp_response(basicOCSPResps);
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
					final RevocationValues revocationValues = RevocationValues.getInstance(attValue);
					for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {

						final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
						addBasicOcspResp(basicOCSPResps, basicOCSPResp);
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
		return basicOCSPResps;
	}

	private void addBasicOcspRespFrom_id_ri_ocsp_response(final List<BasicOCSPResp> basicOCSPResps) {

		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {

			final BasicOCSPResp basicOCSPResp;
			final DERSequence otherRevocationInfoMatch = (DERSequence) object;
			if (otherRevocationInfoMatch.size() == 4) {

				basicOCSPResp = DSSASN1Utils.getBasicOcspResp(otherRevocationInfoMatch);
			} else {

				final OCSPResp ocspResp = DSSASN1Utils.getOcspResp(otherRevocationInfoMatch);
				basicOCSPResp = DSSASN1Utils.getBasicOCSPResp(ocspResp);
			}
			addBasicOcspResp(basicOCSPResps, basicOCSPResp);
		}
	}

	private void addBasicOcspRespFrom_id_pkix_ocsp_basic(final List<BasicOCSPResp> basicOCSPResps) {

		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {

			final DERSequence otherRevocationInfoMatch = (DERSequence) object;
			final BasicOCSPResp basicOCSPResp = DSSASN1Utils.getBasicOcspResp(otherRevocationInfoMatch);
			addBasicOcspResp(basicOCSPResps, basicOCSPResp);
		}
	}

	private void addBasicOcspResp(final List<BasicOCSPResp> basicOCSPResps, final BasicOCSPResp basicOCSPResp) {

		if (basicOCSPResp != null) {
			basicOCSPResps.add(basicOCSPResp);
		}
	}
}
