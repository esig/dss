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
package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.InvalidPasswordException;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ByteRange;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public abstract class AbstractPDFSignatureService implements PDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPDFSignatureService.class);

	protected final PDFServiceMode serviceMode;
	protected final SignatureDrawerFactory signatureDrawerFactory;
	
	protected String passwordProtection;

	/**
	 * Constructor for the PDFSignatureService
	 * 
	 * @param serviceMode
	 *                               current instance is used to generate
	 *                               DocumentTypestamp or Signature signature layer
	 * @param signatureDrawerFactory
	 *                               the factory of {@code SignatureDrawer}
	 */
	protected AbstractPDFSignatureService(PDFServiceMode serviceMode, SignatureDrawerFactory signatureDrawerFactory) {
		this.serviceMode = serviceMode;
		this.signatureDrawerFactory = signatureDrawerFactory;
	}
	

	/**
	 * Specify the used password for the encrypted document
	 * @param pwd the used password
	 */
	@Override
	public void setPasswordProtection(String pwd) {
		this.passwordProtection = pwd;		
	}

	protected boolean isDocumentTimestampLayer() {
		// CONTENT_TIMESTAMP is part of the signature
		return PDFServiceMode.SIGNATURE_TIMESTAMP == serviceMode || PDFServiceMode.ARCHIVE_TIMESTAMP == serviceMode;
	}

	protected String getType() {
		if (isDocumentTimestampLayer()) {
			return PAdESConstants.TIMESTAMP_TYPE;
		} else {
			return PAdESConstants.SIGNATURE_TYPE;
		}
	}

	@Override
	public List<PdfRevision> validateSignatures(DSSDocument document) {
		return getRevisions(document);
	}

	/**
	 * This method checks if the document is not encrypted or with limited edition
	 * rights
	 * 
	 * @param toSignDocument the document which will be modified
	 */
	protected abstract void checkDocumentPermissions(DSSDocument toSignDocument);

	private List<PdfRevision> getRevisions(DSSDocument document) {
		List<PdfRevision> result = new ArrayList<>();
		try (PdfDocumentReader reader = loadPdfDocumentReader(document, passwordProtection)) {

			final PdfDssDict dssDictionary = reader.getDSSDictionary();
			boolean mainDssDictionaryAdded = false;
			
			Map<PdfSignatureDictionary, List<String>> sigDictionaries = reader.extractSigDictionaries();
			sigDictionaries = sortSignatureDictionaries(sigDictionaries); // sort from the latest revision to the first

			for (Map.Entry<PdfSignatureDictionary, List<String>> sigDictEntry : sigDictionaries.entrySet()) {
				PdfSignatureDictionary signatureDictionary = sigDictEntry.getKey();
				List<String> fieldNames = sigDictEntry.getValue();
				try {
					LOG.info("Signature field name: {}", fieldNames);
					
					final ByteRange byteRange = signatureDictionary.getByteRange();
					byteRange.validate();
	
					final byte[] cms = signatureDictionary.getContents();
					byte[] signedContent = DSSUtils.EMPTY_BYTE_ARRAY;
					if (!isContentValueEqualsByteRangeExtraction(document, byteRange, cms, fieldNames)) {
						LOG.warn("Signature {} is skipped. SIWA detected !", fieldNames);
						// TODO : continue ?
					} else {
						signedContent = PAdESUtils.getSignedContent(document, byteRange);
					}
	
					boolean signatureCoversWholeDocument = reader.isSignatureCoversWholeDocument(signatureDictionary);
					
					PdfDssDict previousRevisionDssDict = null;
					// LT or LTA
					if (dssDictionary != null) {
						// obtain covered DSS dictionary if already exist
						previousRevisionDssDict = getDSSDictionaryPresentInRevision(extractBeforeSignatureValue(byteRange, signedContent));
					}
					
					PdfRevision newRevision = null;
	
					if (isDocTimestamp(signatureDictionary)) {
						// if there is a DSS dictionary before -> Archive timestamp
						boolean isArchiveTimestamp = previousRevisionDssDict != null;

						newRevision = new PdfDocTimestampRevision(signatureDictionary, fieldNames, signedContent, signatureCoversWholeDocument,
								isArchiveTimestamp);

					} else if (isSignature(signatureDictionary)) {
						// signature contains all dss dictionaries present after
						newRevision = new PdfSignatureRevision(signatureDictionary, dssDictionary, fieldNames, 
								signedContent, signatureCoversWholeDocument);
	
					} else {
						LOG.warn("The entry {} is skipped. A signature dictionary entry with a type '{}' and subFilter '{}' is not acceptable configuration!",
								fieldNames, signatureDictionary.getType(), signatureDictionary.getSubFilter());
						
					}
					
					boolean dssDictionaryUpdated = previousRevisionDssDict != null && !previousRevisionDssDict.equals(dssDictionary);
					
					// add the main dss dictionary as the first revision
					if (dssDictionaryUpdated && !mainDssDictionaryAdded) {
						result.add(new PdfDocDssRevision(dssDictionary));
					}
					mainDssDictionaryAdded = true;
					
					// add signature/ timestamp revision
					if (newRevision != null) {
						result.add(newRevision);
					}
					
					// add a previous DSS revision
					if (previousRevisionDssDict != null) {
						result.add(new PdfDocDssRevision(previousRevisionDssDict));
					}
					
				} catch (Exception e) {
					String errorMessage = "Unable to parse signature {} . Reason : {}";
					if (LOG.isDebugEnabled()) {
						LOG.error(errorMessage, fieldNames, e.getMessage(), e);
					} else {
						LOG.error(errorMessage, fieldNames, e.getMessage() );
					}
					
				}
			}

		} catch (IOException e) {
			throw new DSSException(String.format("The document with name [%s] is either not accessible or not PDF compatible. Reason : [%s]", 
					document.getName(), e.getMessage()), e); 
		} catch (DSSException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSException("Cannot analyze signatures : " + e.getMessage(), e);
		}
		return result;
	}
	
	/**
	 * Loads {@code PdfDocumentReader} instance
	 * 
	 * @param dssDocument {@link DSSDocument} to read
	 * @param passwordProtection {@link String} the password used to protect the document
	 * @throws IOException in case of loading error
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	protected abstract PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, String passwordProtection) throws IOException, InvalidPasswordException;
	
	/**
	 * Loads {@code PdfDocumentReader} instance
	 * 
	 * @param binaries a byte array
	 * @param passwordProtection {@link String} the password used to protect the document
	 * @throws IOException in case of loading error
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	protected abstract PdfDocumentReader loadPdfDocumentReader(byte[] binaries, String passwordProtection) throws IOException, InvalidPasswordException;
	
	/**
	 * Sorts the given map starting from the latest revision to the first
	 * 
	 * @param pdfSignatureDictionary a map between {@link PdfSignatureDictionary} and list of field names to sort
	 * @return a sorted map
	 */
	private Map<PdfSignatureDictionary, List<String>> sortSignatureDictionaries(Map<PdfSignatureDictionary, List<String>> pdfSignatureDictionary) {
		return pdfSignatureDictionary.entrySet().stream()
				.sorted(Map.Entry.<PdfSignatureDictionary, List<String>>comparingByKey(new PdfSignatureDictionaryComparator()).reversed())
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));
	}
	
	private PdfDssDict getDSSDictionaryPresentInRevision(byte[] originalBytes) {
		try (PdfDocumentReader reader = loadPdfDocumentReader(originalBytes, passwordProtection)) {
			return reader.getDSSDictionary();
		} catch (Exception e) {
			LOG.debug("Cannot extract DSS dictionary from the previous revision : {}", e.getMessage(), e);
			return null;
		}
	}
	
	protected boolean isContentValueEqualsByteRangeExtraction(DSSDocument document, ByteRange byteRange, byte[] cms, List<String> signatureFieldNames) {
		boolean match = false;
		try {
			byte[] cmsWithByteRange = getSignatureValue(document, byteRange);
			match = Arrays.equals(cms, cmsWithByteRange);
			if (!match) {
				LOG.warn("Conflict between /Content and ByteRange for Signature {}.", signatureFieldNames);
			}
		} catch (Exception e) {
			String message = String.format("Unable to retrieve data from the ByteRange : [%s]", byteRange);
			if (LOG.isDebugEnabled()) {
				// Exception displays the (long) hex value
				LOG.debug(message, e);
			} else {
				LOG.error(message);
			}
		}
		return match;
	}
	
	protected byte[] getSignatureValue(DSSDocument dssDocument, ByteRange byteRange) throws IOException {
		// Extracts bytes from 841 to 959. [0, 840, 960, 1200]
		int startSigValueContent = byteRange.getFirstPartStart() + byteRange.getFirstPartEnd() + 1;
		int endSigValueContent = byteRange.getSecondPartStart() - 1;
		
		int signatureValueArraySize = endSigValueContent - startSigValueContent;
		if (signatureValueArraySize < 1) {
			throw new DSSException("The byte range present in the document is not valid! "
					+ "SignatureValue size cannot be negative or equal to zero!");
		}

		byte[] signatureValueArray = new byte[signatureValueArraySize];
		
		try (InputStream is = dssDocument.openStream()) {
			DSSUtils.skipAvailableBytes(is, startSigValueContent);
			DSSUtils.readAvailableBytes(is, signatureValueArray);
		}
		
		return Utils.fromHex(new String(signatureValueArray));
	}

	protected byte[] extractBeforeSignatureValue(ByteRange byteRange, byte[] signedContent) {
		final int length = byteRange.getFirstPartEnd();
		if (signedContent.length < length) {
			return new byte[0];
		}
		final byte[] result = new byte[length];
		System.arraycopy(signedContent, 0, result, 0, length);
		return result;
	}
	
	/**
	 * Checks if the given signature dictionary represents a DocTimeStamp
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a DocTimeStamp, FALSE otherwise
	 */
	protected boolean isDocTimestamp(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.TIMESTAMP_TYPE.equals(type)) && PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
	}

	/**
	 * Checks if the given signature dictionary represents a Signature
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a Signature, FALSE otherwise
	 */
	protected boolean isSignature(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.SIGNATURE_TYPE.equals(type)) && !PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
	}

	/**
	 * This method builds a Map of known Objects (extracted from previous DSS
	 * Dictionaries). This map will be used to avoid duplicate the same objects
	 * between layers.
	 * 
	 * @param callbacks
	 * @return
	 */
	protected Map<String, Long> buildKnownObjects(List<DSSDictionaryCallback> callbacks) {
		Map<String, Long> result = new HashMap<>();
		for (DSSDictionaryCallback callback : callbacks) {

			Map<Long, CertificateToken> storedCertificates = callback.getStoredCertificates();
			for (Entry<Long, CertificateToken> certEntry : storedCertificates.entrySet()) {
				String tokenKey = getTokenDigest(certEntry.getValue());
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, certEntry.getKey());
				}
			}

			Map<Long, BasicOCSPResp> storedOcspResps = callback.getStoredOcspResps();
			for (Entry<Long, BasicOCSPResp> ocspEntry : storedOcspResps.entrySet()) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(ocspEntry.getValue());
				String tokenKey = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, DSSRevocationUtils.getEncoded(ocspResp)));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, ocspEntry.getKey());
				}
			}

			Map<Long, CRLBinary> storedCrls = callback.getStoredCrls();
			for (Entry<Long, CRLBinary> crlEntry : storedCrls.entrySet()) {
				String tokenKey = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, crlEntry.getValue().getBinaries()));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, crlEntry.getKey());
				}
			}
		}
		return result;
	}

	protected String getTokenDigest(Token token) {
		return Utils.toBase64(token.getDigest(DigestAlgorithm.SHA256));
	}

}
