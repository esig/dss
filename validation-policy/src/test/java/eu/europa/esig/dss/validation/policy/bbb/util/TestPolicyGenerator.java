package eu.europa.esig.dss.validation.policy.bbb.util;

import eu.europa.esig.dss.EN319102.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.BasicSignatureConstraints;
import eu.europa.esig.jaxb.policy.CertificateConstraints;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;
import eu.europa.esig.jaxb.policy.SignatureConstraints;

public class TestPolicyGenerator {
	
	public static ValidationPolicy generatePolicy() {
		return generatePolicy(true);
	}

	public static ValidationPolicy generatePolicy(boolean policyMandatory) {
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		LevelConstraint warnLevel = new LevelConstraint();
		warnLevel.setLevel(Level.WARN);
		
		LevelConstraint infoLevel = new LevelConstraint();
		infoLevel.setLevel(Level.INFORM);
		
		ConstraintsParameters policy = new ConstraintsParameters();
		policy.setName("Test policy");

		SignatureConstraints constraints = new SignatureConstraints();
		constraints.setCryptographic(generateCryptographicConstrains());
		
		TestMultiValueConstraint multi = new TestMultiValueConstraint();
		multi.setLevel(Level.FAIL);
		multi.addConstraint("ANY_POLICY");
		if(policyMandatory) {
			multi.addConstraint("NO_POLICY");
		}
		constraints.setAcceptablePolicies(multi);
		
		
		
		BasicSignatureConstraints basic = new BasicSignatureConstraints();
		basic.setCACertificate(generateCertConstraint());
		basic.setReferenceDataExistence(failLevel);
		basic.setReferenceDataIntact(failLevel);
		basic.setSignatureIntact(failLevel);
		basic.setSignatureValid(failLevel);
		basic.setSigningCertificate(generateCertConstraint());
		
		constraints.setBasicSignatureConstraints(basic);
		
		constraints.setStructuralValidation(failLevel);
		
		policy.setSignatureConstraints(constraints);
		
		return new EtsiValidationPolicy(policy);
	}
	
	private static CertificateConstraints generateCertConstraint() {
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		LevelConstraint warnLevel = new LevelConstraint();
		warnLevel.setLevel(Level.WARN);
		
		LevelConstraint infoLevel = new LevelConstraint();
		infoLevel.setLevel(Level.INFORM);
		
		TestMultiValueConstraint keyUsage = new TestMultiValueConstraint();
		keyUsage.setLevel(Level.WARN);
		keyUsage.addConstraint("nonRepudiation");
		
		CertificateConstraints certConstraint = new CertificateConstraints();
		certConstraint.setKeyUsage(keyUsage);
		certConstraint.setAttributePresent(failLevel);
		certConstraint.setCryptographic(generateCryptographicConstrains());
		certConstraint.setDigestValueMatch(failLevel);
		certConstraint.setDigestValuePresent(failLevel);
		certConstraint.setExpiration(failLevel);
		certConstraint.setIssuerSerialMatch(warnLevel);
		certConstraint.setIssuedToLegalPerson(infoLevel);
		certConstraint.setOnHold(failLevel);
		certConstraint.setProspectiveCertificateChain(failLevel);
		certConstraint.setQualification(warnLevel);
		certConstraint.setRecognition(failLevel);
		certConstraint.setRevocationDataAvailable(failLevel);
		certConstraint.setRevocationDataIsTrusted(failLevel);
		certConstraint.setRevocationDataFreshness(warnLevel);
		certConstraint.setRevoked(failLevel);
		certConstraint.setSignature(failLevel);
		certConstraint.setSigned(warnLevel);
		certConstraint.setTSLStatusAndValidity(failLevel);
		certConstraint.setTSLStatus(warnLevel);
		certConstraint.setTSLValidity(warnLevel);
		certConstraint.setSupportedBySSCD(warnLevel);
		
		return certConstraint;
	}

	private static CryptographicConstraint generateCryptographicConstrains() {
		CryptographicConstraint result = new CryptographicConstraint();
		ListAlgo list = new ListAlgo();
		Algo algo = new Algo();
		algo.setValue("DSA");
		algo.setSize("128");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("RSA");
		algo.setSize("1024");
		list.getAlgo().add(algo);
		result.setAcceptableEncryptionAlgo(list);

		list = new ListAlgo();
		algo = new Algo();
		algo.setValue("SHA1");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA224");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA256");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA384");
		list.getAlgo().add(algo);
		result.setAcceptableDigestAlgo(list);

		result.setLevel(Level.FAIL);
		
		return result;
	}
}
