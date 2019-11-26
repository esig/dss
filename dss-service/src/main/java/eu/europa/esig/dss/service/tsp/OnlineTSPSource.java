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
package eu.europa.esig.dss.service.tsp;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.NonceSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
 *
 */
public class OnlineTSPSource implements TSPSource {

	private static final long serialVersionUID = 2327302822894625162L;

	private static final Logger LOG = LoggerFactory.getLogger(OnlineTSPSource.class);

	/**
	 * The URL of the TSP server
	 */
	private String tspServer;

	/**
	 * The requested policy oid
	 */
	private ASN1ObjectIdentifier policyOid;

	/**
	 * The data loader used to retrieve the TSP response.
	 */
	private DataLoader dataLoader;

	/**
	 * This variable is used to prevent the replay attack.
	 */
	private NonceSource nonceSource;

	/**
	 * The default constructor for OnlineTSPSource.
	 */
	public OnlineTSPSource() {
		this(null);
	}

	/**
	 * Build a OnlineTSPSource that will query the specified URL
	 *
	 * @param tspServer
	 *            the tsp URL
	 */
	public OnlineTSPSource(final String tspServer) {
		this.tspServer = tspServer;
	}

	/**
	 * Set the URL of the TSA
	 *
	 * @param tspServer
	 *            the TSA url
	 */
	public void setTspServer(final String tspServer) {
		this.tspServer = tspServer;
	}

	/**
	 * Set the request policy
	 *
	 * @param policyOid
	 *            the policy oid to use
	 */
	public void setPolicyOid(final String policyOid) {
		this.policyOid = new ASN1ObjectIdentifier(policyOid);
	}

	/**
	 * Set the DataLoader to use for querying the TSP server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve the TSP response using HTTP.
	 */
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Set the NonceSource to use for querying the TSP server.
	 *
	 * @param nonceSource
	 *            the component that prevents the replay attack.
	 */
	public void setNonceSource(NonceSource nonceSource) {
		this.nonceSource = nonceSource;
	}

	@Override
	public TimestampBinary getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Timestamp digest algorithm: {}", digestAlgorithm.getName());
				LOG.trace("Timestamp digest value    : {}", Utils.toHex(digest));
			}

			// Setup the time stamp request
			final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
			tsqGenerator.setCertReq(true);
			if (policyOid != null) {
				tsqGenerator.setReqPolicy(policyOid);
			}

			ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(digestAlgorithm.getOid());
			TimeStampRequest timeStampRequest = null;
			if (nonceSource == null) {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest);
			} else {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest, nonceSource.getNonce());
			}

			final byte[] requestBytes = timeStampRequest.getEncoded();

			// Call the communications layer
			if (dataLoader == null) {
				dataLoader = new NativeHTTPDataLoader();
			}
			byte[] respBytes = dataLoader.post(tspServer, requestBytes);

			// Handle the TSA response
			final TimeStampResponse timeStampResponse = new TimeStampResponse(respBytes);

			// Validates token, nonce, policy id, message digest ...
			timeStampResponse.validate(timeStampRequest);

			String statusString = timeStampResponse.getStatusString();
			if (statusString != null) {
				LOG.info("TSP Status: {}", statusString);
			}

			PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
			if (failInfo != null) {
				LOG.warn("TSP Failure info: {}", failInfo);
			}

			final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();

			if (timeStampToken != null) {
				LOG.info("TSP SID : SN {}, Issuer {}", timeStampToken.getSID().getSerialNumber(), timeStampToken.getSID().getIssuer());
			} else {
				throw new DSSException("No retrieved timestamp token (TSP Status : " + statusString + " / " + failInfo + ")");
			}
			return new TimestampBinary(DSSASN1Utils.getDEREncoded(timeStampToken));
		} catch (TSPException e) {
			throw new DSSException("Invalid TSP response", e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

}
