package eu.europa.esig.dss.jades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

//@formatter:off
/**
 * {
 * 
 * "payload":"payload contents",
 * 
 * "signatures":[
 * 
 * {"protected":"integrity-protected header 1 contents",
 * "header":non-integrity-protected header 1 contents, 
 * "signature":"signature 1 contents"},
 * 
 * ...
 * 
 * {"protected":"integrity-protected header N contents",
 * "header":non-integrity-protected header N contents, 
 * "signature":"signature N contents"}
 * 
 * ]
 * 
 * }
 */
//@formatter:on
public class JWSSerializationDocumentValidator extends AbstractJWSDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(JWSSerializationDocumentValidator.class);

	private Map<String, Object> rootStructure;

	public JWSSerializationDocumentValidator() {
	}

	public JWSSerializationDocumentValidator(DSSDocument document) {
		super(document);
		
		try {
			rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(document)));
		} catch (JoseException e) {
			throw new DSSException("Unable to parse the file", e);
		}
	}

	@Override
	public boolean isSupported(DSSDocument document) {
		try (InputStream is = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			int firstChar = is.read();
			if (firstChar == '{') {
				baos.write(firstChar);
				Utils.copy(is, baos);
				if (baos.size() < 2) {
					return false;
				}
				Map<String, Object> json = JsonUtil.parseJson(baos.toString());
				return json != null;
			}
		} catch (JoseException e) {
			LOG.warn("Unable to parse content as JSON : {}", e.getMessage());
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<AdvancedSignature> getSignatures() {
		List<AdvancedSignature> signatures = new ArrayList<>();

		String payloadBase64Url = (String) rootStructure.get(JWSConstants.PAYLOAD);
		byte[] payloadBinaries = JAdESUtils.fromBase64Url(payloadBase64Url);

		List<Map<String, Object>> signaturesList = (List<Map<String, Object>>) rootStructure.get(JWSConstants.SIGNATURES);
		LOG.info("{} signature(s) found", Utils.collectionSize(signaturesList));

		if (Utils.isCollectionNotEmpty(signaturesList)) {
			for (Map<String, Object> signatureObject : signaturesList) {

				try {
					String protectedBase64Url = (String) signatureObject.get(JWSConstants.PROTECTED);
					String signatureBase64Url = (String) signatureObject.get(JWSConstants.SIGNATURE);
					byte[] signatureBinaries = JAdESUtils.fromBase64Url(signatureBase64Url);
					Map<String, Object> header = (Map<String, Object>) signatureObject.get(JWSConstants.HEADER);

					JWS jws = new JWS();
					jws.setPayloadBytes(payloadBinaries);
					jws.setSignature(signatureBinaries);
					jws.setProtected(protectedBase64Url);
					jws.setUnprotected(header);
					
					JAdESSignature jadesSignature = new JAdESSignature(jws);
					signatures.add(jadesSignature);
				} catch (Exception e) {
					throw new DSSException(String.format("Unable to build a signature. Reason : [%s]", e.getMessage()), e);
				}
			}
		}

		return signatures;
	}

}
