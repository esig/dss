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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.NonceSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

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
	 * Builds an OnlineTSPSource that will query the specified URL with default {@code TimestampDataLoader}
	 *
	 * @param tspServer
	 *            the tsp URL
	 */
	public OnlineTSPSource(final String tspServer) {
		this.tspServer = tspServer;
		this.dataLoader = new TimestampDataLoader();
		LOG.trace("+OnlineTSPSource with the default data loader.");
	}

	/**
	 * Builds an OnlineTSPSource that will query the URL and the specified {@code DataLoader}
	 *
	 * @param tspServer
	 *            the tsp URL
	 * @param dataLoader
	 *            {@link DataLoader} to retrieve the TSP
	 */
	public OnlineTSPSource(final String tspServer, final DataLoader dataLoader) {
		this.tspServer = tspServer;
		this.dataLoader = dataLoader;
		LOG.trace("+OnlineTSPSource with the specific data loader.");
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
			Objects.requireNonNull(dataLoader, "DataLoader is not provided !");
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
			TimeStampRequest timeStampRequest;
			if (nonceSource == null) {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest);
			} else {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest, nonceSource.getNonce());
			}

			final byte[] requestBytes = timeStampRequest.getEncoded();

			// Call the communications layer
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
				throw new DSSExternalResourceException(String.format("No timestamp token has been retrieved " +
								"(TSP Status : %s / %s)", statusString, failInfo));
			}
			return new TimestampBinary(DSSASN1Utils.getDEREncoded(timeStampToken));
		} catch (TSPException e) {
			throw new DSSExternalResourceException(String.format("Invalid TSP response : %s", e.getMessage()), e);
		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format(
					"An error occurred during timestamp request : %s", e.getMessage()), e);
		}
	}

}
