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
package eu.europa.esig.dss.simplereport;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A SimpleReport holder to fetch values from a JAXB SimpleReport.
 */
public class SimpleReport {

	/** The JAXB Simple report */
	private final XmlSimpleReport wrapped;

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link XmlSimpleReport}
	 */
	public SimpleReport(final XmlSimpleReport wrapped) {
		this.wrapped = wrapped;
	}

	/**
	 * This method returns the validation time.
	 *
	 * @return the validation time
	 */
	public Date getValidationTime() {
		return wrapped.getValidationTime();
	}

	/**
	 * This method returns the indication obtained after the validation of a token.
	 *
	 * @param tokenId
	 *            DSS unique identifier of the token
	 * @return the indication for the given token Id
	 */
	public Indication getIndication(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null) {
			return token.getIndication();
		}
		return null;
	}

	/**
	 * This method returns the sub-indication obtained after the validation of the token.
	 *
	 * @param tokenId
	 *            DSS unique identifier of the token
	 * @return the sub-indication for the given token Id
	 */
	public SubIndication getSubIndication(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null) {
			return token.getSubIndication();
		}
		return null;
	}

	/**
	 * This method checks if a signature is valid (TOTAL_PASSED) or
	 * timestamp validation PASSED
	 * 
	 * @param tokenId
	 *            a token id to get a result for
	 * @return true if the signature Indication element is equals to {@link Indication#TOTAL_PASSED} or
	 * 		   the timestamp Indication element is Equals to {@link Indication#PASSED}
	 */
	public boolean isValid(final String tokenId) {
		final Indication indicationValue = getIndication(tokenId);
		return Indication.TOTAL_PASSED.equals(indicationValue) || Indication.PASSED.equals(indicationValue);
	}

	/**
	 * This method retrieves the signature ids
	 * 
	 * @return the {@code List} of signature id(s) contained in the simpleReport
	 */
	public List<String> getSignatureIdList() {
		final List<String> signatureIdList = new ArrayList<>();
		List<XmlToken> tokens = wrapped.getSignatureOrTimestamp();
		if (tokens != null) {
			for (XmlToken token : tokens) {
				if (token instanceof XmlSignature) {
					signatureIdList.add(token.getId());
				}
			}
		}
		return signatureIdList;
	}

	/**
	 * This method retrieves the timestamp ids
	 * 
	 * @return the {@code List} of timestamp id(s) contained in the simpleReport
	 */
	public List<String> getTimestampIdList() {
		final List<String> timestampIdList = new ArrayList<>();
		List<XmlToken> tokens = wrapped.getSignatureOrTimestamp();
		if (tokens != null) {
			for (XmlToken token : tokens) {
				if (token instanceof XmlTimestamp) {
					timestampIdList.add(token.getId());
				}
			}
		}
		return timestampIdList;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return the first signature id
	 */
	public String getFirstSignatureId() {
		final List<String> signatureIdList = getSignatureIdList();
		if (signatureIdList.size() > 0) {
			return signatureIdList.get(0);
		}
		return null;
	}

	/**
	 * This method returns the first timestamp id.
	 *
	 * @return the first timestamp id
	 */
	public String getFirstTimestampId() {
		final List<String> timestampIdList = getTimestampIdList();
		if (timestampIdList.size() > 0) {
			return timestampIdList.get(0);
		}
		return null;
	}
	
	/**
	 * Returns a file name for the validated document
	 * 
	 * @return {@link String} document file name
	 */
	public String getDocumentFilename() {
		return wrapped.getDocumentName();
	}
	
	/**
	 * Returns a file name for a given tokenId
	 * 
	 * @param tokenId 
	 * 		  	  {@link String} id of a token to get its original filename
	 * @return {@link String} file name
	 */
	public String getTokenFilename(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null) {
			return token.getFilename();
		}
		return null;
	}
	
	/**
	 * Returns a certificate chain a given tokenId
	 * 
	 * @param tokenId 
	 * 			  {@link String} id of a token to get its certificate chain
	 * @return {@link XmlCertificateChain} for the token
	 */
	public XmlCertificateChain getCertificateChain(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null) {
			return token.getCertificateChain();
		}
		return null;
	}

	/**
	 * This method retrieve the validation process's errors for a given token by id
	 * 
	 * @param tokenId
	 *            the token id
	 * @return the linked errors
	 */
	public List<Message> getValidationErrors(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getValidationDetails() != null) {
			return convert(token.getValidationDetails().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the validation process's warnings for a given token by id
	 * 
	 * @param tokenId
	 *            the token id
	 * @return the linked warnings
	 */
	public List<Message> getValidationWarnings(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getValidationDetails() != null) {
			return convert(token.getValidationDetails().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieves the validation process's information for a given token by id
	 *
	 * @param tokenId
	 *            the token id
	 * @return the linked information
	 */
	public List<Message> getValidationInfo(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getValidationDetails() != null) {
			return convert(token.getValidationDetails().getInfo());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's errors for a given token by id
	 *
	 * @param tokenId
	 *            the token id
	 * @return the linked errors
	 */
	public List<Message> getQualificationErrors(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getQualificationDetails() != null) {
			return convert(token.getQualificationDetails().getError());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the qualification process's warnings for a given token by id
	 *
	 * @param tokenId
	 *            the token id
	 * @return the linked warnings
	 */
	public List<Message> getQualificationWarnings(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getQualificationDetails() != null) {
			return convert(token.getQualificationDetails().getWarning());
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieves the qualification process's information for a given token by id
	 *
	 * @param tokenId
	 *            the token id
	 * @return the linked information
	 */
	public List<Message> getQualificationInfo(final String tokenId) {
		XmlToken token = getTokenById(tokenId);
		if (token != null && token.getQualificationDetails() != null) {
			return convert(token.getQualificationDetails().getInfo());
		}
		return Collections.emptyList();
	}

	private Message convert(XmlMessage v) {
		if (v != null) {
			return new Message(v.getKey(), v.getValue());
		}
		return null;
	}

	private List<Message> convert(Collection<XmlMessage> messages) {
		if (messages != null) {
			return messages.stream().map(m -> convert(m)).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the signature type: QES, AdES, AdESqc, NA
	 *
	 * @param signatureId
	 *            the signature id to test
	 * @return the {@code SignatureQualification} of the given signature
	 */
	public SignatureQualification getSignatureQualification(final String signatureId) {
		SignatureQualification qualif = SignatureQualification.NA;
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null && signature.getSignatureLevel() != null) {
			qualif = signature.getSignatureLevel().getValue();
		}
		return qualif;
	}

	/**
	 * This method returns the signature format (XAdES_BASELINE_B...)
	 *
	 * @param signatureId
	 *            the signature id
	 * @return the linked signature format
	 */
	public SignatureLevel getSignatureFormat(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSignatureFormat();
		}
		return null;
	}

	/**
	 * This method returns the best-signature-time
	 *
	 * @param signatureId
	 *            the signature id
	 * @return the best signing time
	 */
	public Date getBestSignatureTime(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getBestSignatureTime();
		}
		return null;
	}

	/**
	 * This method returns the signature time
	 *
	 * @param signatureId
	 *            the signature id
	 * @return the signing time
	 */
	public Date getSigningTime(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSigningTime();
		}
		return null;
	}

	/**
	 * If the signature validation is TOTAL_PASSED, the result date is the date from
	 * when a signature extension is useful (all certificates can be covered by an
	 * usable revocation data).
	 * 
	 * @param signatureId the signature id
	 * @return the minimal useful date for a signature extension (or null)
	 */
	public Date getSignatureExtensionPeriodMin(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getExtensionPeriodMin();
		}
		return null;
	}

	/**
	 * If the signature validation is TOTAL_PASSED, the result date is the maximum
	 * possible date to extend the signature (before the expiration of the signing
	 * certificate or the latest timestamping certificate).
	 * 
	 * @param signatureId the signature id
	 * @return the maximum useful date for a signature extension (or null)
	 */
	public Date getSignatureExtensionPeriodMax(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getExtensionPeriodMax();
		}
		return null;
	}

	/**
	 * This method returns the signature's signer name
	 *
	 * @param signatureId
	 *            the signature id
	 * @return the signatory
	 */
	public String getSignedBy(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSignedBy();
		}
		return "";
	}

	/**
	 * This method returns the number of signatures
	 * 
	 * @return the number of signatures
	 */
	public int getSignaturesCount() {
		return wrapped.getSignaturesCount();
	}

	/**
	 * This method returns the number of valid signatures
	 * 
	 * @return the number of valid signatures
	 */
	public int getValidSignaturesCount() {
		return wrapped.getValidSignaturesCount();
	}

	/**
	 * This method returns the timestamp production time
	 *
	 * @param timestampId
	 *            the timestamp id
	 * @return the production time
	 */
	public Date getProductionTime(final String timestampId) {
		XmlTimestamp xmlTimestamp = getTimestampById(timestampId);
		if (xmlTimestamp != null) {
			return xmlTimestamp.getProductionTime();
		}
		return null;
	}

	/**
	 * This method returns the timestamp's producer name
	 *
	 * @param timestampId
	 *            the timestamp id
	 * @return a name of the timestamp's producer
	 */
	public String getProducedBy(final String timestampId) {
		XmlTimestamp xmlTimestamp = getTimestampById(timestampId);
		if (xmlTimestamp != null) {
			return xmlTimestamp.getProducedBy();
		}
		return "";
	}

	/**
	 * This method returns the timestamp's qualification
	 *
	 * @param timestampId
	 *                    the timestamp id
	 * @return {@link TimestampQualification} for a given timestamp
	 */
	public TimestampQualification getTimestampQualification(final String timestampId) {
		XmlTimestamp xmlTimestamp = getTimestampById(timestampId);
		if (xmlTimestamp != null && xmlTimestamp.getTimestampLevel() != null) {
			return xmlTimestamp.getTimestampLevel().getValue();
		}
		return null;
	}

	/**
	 * This method returns a wrapper for the given token id
	 * 
	 * @param tokenId
	 *            the token id
	 * @return the wrapper for the given token id
	 */
	private XmlToken getTokenById(String tokenId) {
		List<XmlToken> tokens = wrapped.getSignatureOrTimestamp();
		if (tokens != null) {
			for (XmlToken token : tokens) {
				if (tokenId.equals(token.getId())) {
					return token;
				}
			}
		}
		return null;
	}

	/**
	 * This method returns a wrapper for the given signature
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the wrapper for the given signature id
	 */
	private XmlSignature getSignatureById(String signatureId) {
		XmlToken token = getTokenById(signatureId);
		if (token != null && token instanceof XmlSignature) {
			return (XmlSignature) token;
		}
		return null;
	}

	/**
	 * This method returns a wrapper for the given timestamp
	 * 
	 * @param timestampId
	 *            the timestamp id
	 * @return the wrapper for the given timestamp id
	 */
	private XmlTimestamp getTimestampById(String timestampId) {
		XmlToken token = getTokenById(timestampId);
		if (token != null && token instanceof XmlTimestamp) {
			return (XmlTimestamp) token;
		}
		return null;
	}

	/**
	 * This method returns a list of timestamps for a signature with the given id
	 *
	 * @param signatureId
	 *            the signature id
	 * @return list if timestamp wrappers
	 */
	public List<XmlTimestamp> getSignatureTimestamps(String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null && xmlSignature.getTimestamps() != null) {
			return xmlSignature.getTimestamps().getTimestamp();
		}
		return Collections.emptyList();
	}

	/**
	 * This methods returns the jaxb model of the simple report
	 * 
	 * @return the jaxb model
	 */
	public XmlSimpleReport getJaxbModel() {
		return wrapped;
	}

}
