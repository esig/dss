package eu.europa.esig.dss.validation;

import static eu.europa.esig.dss.OID.attributeRevocationRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.x509.revocation.ocsp.SignatureOCSPSource;

/**
 * OCSPSource that retrieves information from a {@link CMSSignedData} container.
 *
 */
@SuppressWarnings("serial")
public abstract class CMSOCSPSource extends SignatureOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSOCSPSource.class);

	protected transient final CMSSignedData cmsSignedData;
	protected transient final AttributeTable unsignedAttributes;
	
	/**
	 * Cached list of {@code OCSPResponseBinary}s found in SignedData attribute
	 */
	private List<OCSPResponseBinary> signedDataOCSPIdentifiers = new ArrayList<OCSPResponseBinary>();

	/**
	 * The default constructor for CAdESOCSPSource.
	 *
	 * @param cms
	 *            {@link CMSSignedData}
	 * @param unsignedAttributes
	 *            {@link AttributeTable} unsignedAttributes
	 */
	protected CMSOCSPSource(final CMSSignedData cms, final AttributeTable unsignedAttributes) {
		this.cmsSignedData = cms;
		this.unsignedAttributes = unsignedAttributes;
		appendContainedOCSPResponses();
	}
	
	/**
	 * Returns revocation-values {@link RevocationOrigin}
	 * @return {@link RevocationOrigin}
	 */
	protected RevocationOrigin getRevocationValuesOrigin() {
		return RevocationOrigin.REVOCATION_VALUES;
	}

	/**
	 * Returns complete-revocation-refs {@link RevocationOrigin}
	 * @return {@link RevocationOrigin}
	 */
	protected RevocationOrigin getCompleteRevocationRefsOrigin() {
		return RevocationOrigin.COMPLETE_REVOCATION_REFS;
	}

	/**
	 * Returns attribute-revocation-refs {@link RevocationOrigin}
	 * @return {@link RevocationOrigin}
	 */
	protected RevocationOrigin getAttributeRevocationRefsOrigin() {
		return RevocationOrigin.ATTRIBUTE_REVOCATION_REFS;
	}
	
	/**
	 * Returns a list of {@code OCSPResponseIdentifier} found in the SignedData container
	 * @return list of {@link OCSPResponseBinary}
	 */
	public List<OCSPResponseBinary> getSignedDataOCSPIdentifiers() {
		return signedDataOCSPIdentifiers;
	}

	@Override
	public void appendContainedOCSPResponses() {
		
		// Add OCSPs from SignedData
		collectFromSignedData();

		if (unsignedAttributes != null) {

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
			collectRevocationValues(unsignedAttributes, id_aa_ets_revocationValues, getRevocationValuesOrigin());
			
			/*
			 * ETSI TS 101 733 V2.2.1 (2013-04) pages 39,41
			 * 6.2.2 complete-revocation-references Attribute Definition and
			 * 6.2.4 attribute-revocation-references Attribute Definition
			 * The complete-revocation-references attribute is an unsigned attribute. 
			 * Only a single instance of this
			 * attribute shall occur with an electronic signature. 
			 * It references the full set of the CRL, ACRL, or OCSP responses that
			 * have been used in the validation of the signer, and 
			 * CA certificates used in ES with Complete validation data.
			 * The complete-revocation-references attribute value has the ASN.1 syntax CompleteRevocationRefs
			 * 
			 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
			 * CrlOcspRef ::= SEQUENCE {
			 *  crlids [0] CRLListID OPTIONAL,
			 *  ocspids [1] OcspListID OPTIONAL,
			 *  otherRev [2] OtherRevRefs OPTIONAL
			 * } 
			 * AttributeRevocationRefs ::= SEQUENCE OF CrlOcspRef (the same as for CompleteRevocationRefs)
			 */
			collectRevocationRefs(unsignedAttributes, id_aa_ets_revocationRefs, getCompleteRevocationRefsOrigin());
			/*
			 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45} 
			 */
			collectRevocationRefs(unsignedAttributes, attributeRevocationRefsOid, getAttributeRevocationRefsOrigin());

		}

		/* TODO (pades): Read revocation data from from unsigned attribute  1.2.840.113583.1.1.8
          In the PKCS #7 object of a digital signature in a PDF file, identifies a signed attribute
          that "can include all the revocation information that is necessary to carry out revocation
          checks for the signer's certificate and its issuer certificates."
          Defined as adbe-revocationInfoArchival { adbe(1.2.840.113583) acrobat(1) security(1) 8 } in "PDF Reference, 
          fifth edition: Adobe® Portable Document Format, Version 1.6" Adobe Systems Incorporated, 2004.
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
	}

	private void collectFromSignedData() {
		addBasicOcspRespFrom_id_ri_ocsp_response();
		addBasicOcspRespFrom_id_pkix_ocsp_basic();
	}

	private void addBasicOcspRespFrom_id_ri_ocsp_response() {
		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof DERSequence) {
				final DERSequence otherRevocationInfoMatch = (DERSequence) object;
				final BasicOCSPResp basicOCSPResp;
				if (otherRevocationInfoMatch.size() == 4) {
					basicOCSPResp = DSSRevocationUtils.getBasicOcspResp(otherRevocationInfoMatch);
				} else {
					final OCSPResp ocspResp = DSSRevocationUtils.getOcspResp(otherRevocationInfoMatch);
					basicOCSPResp = DSSRevocationUtils.fromRespToBasic(ocspResp);
				}
				OCSPResponseBinary ocspResponseIdentifier = addBasicOcspResp(basicOCSPResp, getRevocationValuesOrigin());
				if (ocspResponseIdentifier != null) {
					ocspResponseIdentifier.setAsn1ObjectIdentifier(CMSObjectIdentifiers.id_ri_ocsp_response);
					signedDataOCSPIdentifiers.add(ocspResponseIdentifier);
				}
			} else {
				LOG.warn("Unsupported object type for id_ri_ocsp_response (SHALL be DER encoding) : {}",
						object.getClass().getSimpleName());
			}
		}
	}

	private void addBasicOcspRespFrom_id_pkix_ocsp_basic() {
		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof DERSequence) {
				final DERSequence otherRevocationInfoMatch = (DERSequence) object;
				final BasicOCSPResp basicOCSPResp = DSSRevocationUtils.getBasicOcspResp(otherRevocationInfoMatch);
				OCSPResponseBinary ocspResponseIdentifier = addBasicOcspResp(basicOCSPResp, getRevocationValuesOrigin());
				if (ocspResponseIdentifier != null) {
					ocspResponseIdentifier.setAsn1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
					signedDataOCSPIdentifiers.add(ocspResponseIdentifier);
				}
			} else {
				LOG.warn("Unsupported object type for id_pkix_ocsp_basic (SHALL be DER encoding) : {}",
						object.getClass().getSimpleName());
			}
		}
	}
	
	private void collectRevocationValues(AttributeTable unsignedAttributes, ASN1ObjectIdentifier revocacationValuesAttribute, RevocationOrigin origin) {
		final Attribute attribute = unsignedAttributes.get(revocacationValuesAttribute);
		if (attribute != null) {

			final ASN1Set attrValues = attribute.getAttrValues();
			final ASN1Encodable attValue = attrValues.getObjectAt(0);
			final RevocationValues revocationValues = RevocationValues.getInstance(attValue);
			for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {

				final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
				addBasicOcspResp(basicOCSPResp, origin);
			}
			/* TODO: should add also OtherRevVals, but:
			 "The syntax and semantics of the other revocation values (OtherRevVals) are outside the scope of the present
            document. The definition of the syntax of the other form of revocation information is as identified by
            OtherRevRefType."
			 */
		}
	}
	
	private void collectRevocationRefs(AttributeTable unsignedAttributes, ASN1ObjectIdentifier revocationReferencesAttribute, RevocationOrigin origin) {
		final Attribute attribute = unsignedAttributes.get(revocationReferencesAttribute);
		if (attribute == null) {
			return;
		}
		final ASN1Set attrValues = attribute.getAttrValues();
		if (attrValues.size() <= 0) {
			return;
		}
	
		final ASN1Encodable attrValue = attrValues.getObjectAt(0);
		final ASN1Sequence completeRevocationRefs = (ASN1Sequence) attrValue;
		for (int i = 0; i < completeRevocationRefs.size(); i++) {
	
			final CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeRevocationRefs.getObjectAt(i));
			final OcspListID ocspListID = otherCertId.getOcspids();
			if (ocspListID != null) {
				for (final OcspResponsesID ocspResponsesID : ocspListID.getOcspResponses()) {
					final OCSPRef ocspRef = new OCSPRef(ocspResponsesID, origin);
					addReference(ocspRef, origin);
				}
			}
		}
	}

	/**
	 * Builds and returns {@code OCSPResponseBinary} from the provided {@code basicOCSPResp}
	 * @param basicOCSPResp {@link BasicOCSPResp} to build identifier from
	 * @param origin {@link RevocationOrigin} specifing the list to store the value
	 * @return {@link OCSPResponseBinary}
	 */
	protected OCSPResponseBinary addBasicOcspResp(final BasicOCSPResp basicOCSPResp, RevocationOrigin origin) {
		if (basicOCSPResp != null) {
			OCSPResponseBinary ocspResponse = OCSPResponseBinary.build(basicOCSPResp);
			addOCSPResponse(ocspResponse, origin);
			return ocspResponse;
		}
		return null;
	}


}
