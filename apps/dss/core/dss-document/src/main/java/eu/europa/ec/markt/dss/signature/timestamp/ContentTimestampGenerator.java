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

package eu.europa.ec.markt.dss.signature.timestamp;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * From RFC 3216, section 3.12.4:
 * The content time-stamp attribute is an attribute which is the time-
 * stamp of the signed data content before it is signed.
 * <p/>
 * The content time-stamp attribute must be a signed attribute.
 * <p/>
 * The following object identifier identifies the signer-attribute
 * attribute:
 * <p/>
 * id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1)
 * member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 * smime(16) id-aa(2) 20}
 * <p/>
 * Content time-stamp attribute values have ASN.1 type ContentTimestamp:
 * ContentTimestamp::= TimeStampToken
 * <p/>
 * The value of messageImprint field within TimeStampToken must be a
 * hash of the value of eContent field within encapContentInfo within
 * the signedData.
 * <p/>
 * From ETSI 101 733 v2.2:
 * ----------------------
 * The content-time-stamp attribute is an attribute that is the time-stamp token of the signed data content before it
 * is signed.
 * The content-time-stamp attribute shall be a signed attribute.
 * The following object identifier identifies the content-time-stamp attribute:
 * id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 20}
 * <p/>
 * content-time-stamp attribute values have ASN.1 type ContentTimestamp:
 * ContentTimestamp::= TimeStampToken
 * <p/>
 * The value of messageImprint of TimeStampToken (as described in RFC 3161 [7]) shall be a hash of the
 * message digest as defined in clause 5.6.1 of the present document.
 * For further information and definition of TimeStampToken, see clause 7.4.
 * ETSI
 * 36 ETSI TS 101 733 V2.2.1 (2013-04)
 * NOTE: content-time-stamp indicates that the signed information was formed before the date included in
 * the content-time-stamp.
 */

public class ContentTimestampGenerator {

	private final String DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD = CanonicalizationMethod.EXCLUSIVE;

	//The timestamping authority
	private TSPSource tspSource;

	private CertificatePool certificatePool;

	private TimestampParameters timestampParameters;

	public ContentTimestampGenerator() {
	}

	/**
	 * @param tspSource       the timestamping authority
	 * @param certificatePool
	 */
	public ContentTimestampGenerator(final TSPSource tspSource, final CertificatePool certificatePool) {
		this.tspSource = tspSource;
		this.certificatePool = certificatePool;
	}

	public CertificatePool getCertificatePool() {
		return certificatePool;
	}

	public void setCertificatePool(CertificatePool certificatePool) {
		this.certificatePool = certificatePool;
	}

	public TSPSource getTspSource() {
		return tspSource;
	}

	public void setTspSource(TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	public void setTimestampParameters(TimestampParameters parameters) {
		timestampParameters = parameters;
	}

	public TimestampParameters getTimestampParameters() {
		return timestampParameters;
	}

	/**
	 * @param timestampType
	 * @return
	 */
	public TimestampToken generateTimestampToken(final TimestampType timestampType, final DigestAlgorithm digestAlgorithm, final byte[] references) {

		final TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, references);
		TimestampToken token = new TimestampToken(timeStampResponse, timestampType, certificatePool);
		return token;
	}

}
